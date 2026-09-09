#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "xdp_lb_common.h"

/*
 * XDP DSR load balance
 *
 * Load-balancer flow:
 *   parse -> detect fragments -> find VIP -> hash
                -> if later frag first -> store backend in frag cache
                    else first frag -> make it to sample backend -> store backend in frag cache
 *         -> find backend
 *         -> encapsulate with IPv4-in-IPv4 -> redirect
 */

#define IPV4_FAMILY 2
#define DEFAULT_TTL 64
#define IPV4_DF 0x4000
#define IPV4_FRAG_BITS (0x2000 | 0x1fff)
#define IPV4_FRAG_OFFSET_MASK 0x1fff
#define DEVICE_IP_KEY 0
#define ENCAPSULATION_FAILED 0
#define ENCAPSULATION_SUCCESS 1

#define PARSE_RESULT_UNSUPPORTED -1
#define PARSE_RESULT_FRAGMENT_FIRST -2
#define PARSE_RESULT_FRAGMENT_LATER -3

#define FRAGMENT_RESULT_PASS 0
#define FRAGMENT_RESULT_FOUND 1
#define FRAGMENT_RESULT_DROP 2

struct flow_key {
    __be32 source_address;
    __be32 destination_address;
    __be16 source_port;
    __be16 destination_port;
    __u8 protocol;
};

struct layer4_ports {
    __be16 source;
    __be16 destination;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct vip_key);
    __type(value, struct vip_value);
} vip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct backend_key);
    __type(value, struct backend);
} backend_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct device_config);
} device_ip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, FRAG_CACHE_MAX_ENTRIES);
    __type(key, struct frag_key);
    __type(value, struct frag_entry);
} frag_cache_map SEC(".maps");

/* ------------------------------- Parser ------------------------------ */

static __always_inline int is_first_fragment(const struct iphdr *ipv4)
{
    return (bpf_ntohs(ipv4->frag_off) & IPV4_FRAG_OFFSET_MASK) == 0;
}

static __always_inline int
parse_client_packet(struct xdp_md *ctx, struct vip_key *vip,
                    struct flow_key *flow, struct iphdr **out_ipv4)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *ethernet = data;
    struct iphdr *ipv4;
    struct layer4_ports *ports;
    __u32 ipv4_length;
    __u32 total_length;
    __u32 available_length;
    int is_fragment;

    if ((void *)(ethernet + 1) > data_end || ethernet->h_proto != bpf_htons(ETH_P_IP))
        return PARSE_RESULT_UNSUPPORTED;

    ipv4 = (void *)(ethernet + 1);
    if ((void *)(ipv4 + 1) > data_end)
        return PARSE_RESULT_UNSUPPORTED;

    ipv4_length = ipv4->ihl * 4;
    total_length = bpf_ntohs(ipv4->tot_len);
    available_length = data_end - (void *)ipv4;
    if (ipv4->version != 4 ||
        ipv4_length < sizeof(*ipv4) ||
        total_length < ipv4_length ||
        total_length > available_length)
        return PARSE_RESULT_UNSUPPORTED;

    *out_ipv4 = ipv4;
    is_fragment = bpf_ntohs(ipv4->frag_off) & IPV4_FRAG_BITS;

    if (is_fragment && !is_first_fragment(ipv4))
        return PARSE_RESULT_FRAGMENT_LATER;

    if (ipv4->protocol != IPPROTO_TCP && ipv4->protocol != IPPROTO_UDP)
        return PARSE_RESULT_UNSUPPORTED;

    ports = (void *)ipv4 + ipv4_length;
    if (ipv4_length + sizeof(*ports) > total_length || (void *)(ports + 1) > data_end)
        return PARSE_RESULT_UNSUPPORTED;

    vip->address = ipv4->daddr;
    vip->port = ports->destination;
    vip->protocol = ipv4->protocol;
    vip->padding = 0;

    flow->source_address = ipv4->saddr;
    flow->destination_address = ipv4->daddr;
    flow->source_port = ports->source;
    flow->destination_port = ports->destination;
    flow->protocol = ipv4->protocol;
    return is_fragment ? PARSE_RESULT_FRAGMENT_FIRST : 0;
}

/* --------------------------- Fragment cache --------------------------- */

static __always_inline void
parse_fragment_key(const struct iphdr *ipv4, struct frag_key *key)
{
    key->source_address = ipv4->saddr;
    key->destination_address = ipv4->daddr;
    key->identification = ipv4->id;
    key->protocol = ipv4->protocol;
    key->padding = 0;
}

/* ------------------------- Hash ------------------------- */
static __always_inline __u32 mix_hash(__u32 hash, __u32 value)
{
    return (hash ^ value) * 16777619u;
}

static __always_inline __u32 flow_hash(const struct flow_key *flow)
{
    __u32 ports = ((__u32)flow->source_port << 16) | flow->destination_port;
    __u32 hash = 2166136261u;

    hash = mix_hash(hash, flow->source_address);
    hash = mix_hash(hash, flow->destination_address);
    hash = mix_hash(hash, ports);
    return mix_hash(hash, flow->protocol);
}

static __always_inline struct backend *
select_backend(const struct vip_key *vip,
               const struct vip_value *vip_value,
               const struct flow_key *flow)
{
    struct backend_key key = {};
    __u32 backend_count = vip_value->backend_count;
    if (backend_count == 0 || backend_count > MAX_BACKENDS_PER_VIP)
        return 0;
    key.vip = *vip;
    key.slot = flow_hash(flow) % backend_count;

    return bpf_map_lookup_elem(&backend_map, &key);
}

static __always_inline int
handle_first_fragment(const struct frag_key *key, const struct flow_key *flow,
                      __be32 backend_address, struct backend *out_backend)
{
    struct frag_entry candidate = {};
    struct frag_entry *existing;
    __u64 now = bpf_ktime_get_ns();

    candidate.backend_address = backend_address;
    candidate.source_port = flow->source_port;
    candidate.destination_port = flow->destination_port;
    candidate.expires_at_ns = now + FRAG_TIMEOUT_NS;

    if (!bpf_map_update_elem(&frag_cache_map, key, &candidate, BPF_NOEXIST)) {
        out_backend->address = candidate.backend_address;
        return FRAGMENT_RESULT_FOUND;
    }

    /* Someone else's entry is already there; find out whose. */
    existing = bpf_map_lookup_elem(&frag_cache_map, key);
    if (!existing)
        return FRAGMENT_RESULT_PASS;

    if (existing->expires_at_ns <= now) {
        if (bpf_map_update_elem(&frag_cache_map, key, &candidate, BPF_EXIST))
            return FRAGMENT_RESULT_PASS;
        out_backend->address = candidate.backend_address;
        return FRAGMENT_RESULT_FOUND;
    }

    if (existing->source_port != candidate.source_port ||
        existing->destination_port != candidate.destination_port)
        return FRAGMENT_RESULT_DROP;

    out_backend->address = existing->backend_address;
    return FRAGMENT_RESULT_FOUND;
}

/* Later fragment: use whatever the first fragment already committed. */
static __always_inline int
handle_later_fragment(const struct frag_key *key, struct backend *out_backend)
{
    struct frag_entry *existing = bpf_map_lookup_elem(&frag_cache_map, key);

    if (!existing || existing->expires_at_ns <= bpf_ktime_get_ns())
        return FRAGMENT_RESULT_PASS;

    out_backend->address = existing->backend_address;
    return FRAGMENT_RESULT_FOUND;
}

/* ------------------------------- Built Packet ------------------------------ */

static __always_inline __sum16 ipv4_checksum(const struct iphdr *ipv4)
{
    const __u16 *words = (const __u16 *)ipv4;
    __u32 sum = 0;

    for (__u32 i = 0; i < sizeof(*ipv4) / sizeof(*words); i++)
        sum += words[i];

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static __always_inline void
build_outer_ipv4(struct iphdr *ipv4, __u16 total_length,
                 __be32 source, __be32 destination)
{
    ipv4->version = 4;
    ipv4->ihl = sizeof(*ipv4) / 4;
    ipv4->tos = 0;
    ipv4->tot_len = bpf_htons(total_length);
    ipv4->id = 0;
    ipv4->frag_off = bpf_htons(IPV4_DF);
    ipv4->ttl = DEFAULT_TTL;
    ipv4->protocol = IPPROTO_IPIP;
    ipv4->saddr = source;
    ipv4->daddr = destination;
    ipv4->check = 0;
    ipv4->check = ipv4_checksum(ipv4);
}

static __always_inline int
encapsulate_packet(struct xdp_md *ctx,
                   const struct device_config *device,
                   const struct backend *backend,
                   struct bpf_fib_lookup *route,
                   int *failure_action)
{
    const int added_size = sizeof(struct iphdr);
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *ethernet = data;
    struct iphdr *inner_ipv4;
    __u32 inner_size;
    __u32 outer_ip_size;
    struct ethhdr *outer_ethernet;
    struct iphdr *outer_ipv4;
    int fib_result;

    *failure_action = XDP_PASS;

    if ((void *)(ethernet + 1) > data_end)
        return ENCAPSULATION_FAILED;

    inner_ipv4 = (void *)(ethernet + 1);
    if ((void *)(inner_ipv4 + 1) > data_end)
        return ENCAPSULATION_FAILED;

    inner_size = bpf_ntohs(inner_ipv4->tot_len);
    if (inner_size > 0xffff - sizeof(struct iphdr))
        return ENCAPSULATION_FAILED;
    outer_ip_size = sizeof(struct iphdr) + inner_size;

    route->family = IPV4_FAMILY;
    route->ifindex = ctx->ingress_ifindex;
    route->l4_protocol = IPPROTO_IPIP;
    route->tot_len = outer_ip_size;
    route->ipv4_src = device->ip_address;
    route->ipv4_dst = backend->address;

    fib_result = bpf_fib_lookup(ctx, route, sizeof(*route), 0);
    if (fib_result == BPF_FIB_LKUP_RET_NO_NEIGH)
        return ENCAPSULATION_FAILED;
    if (fib_result != BPF_FIB_LKUP_RET_SUCCESS)
        return ENCAPSULATION_FAILED;

    if (bpf_xdp_adjust_head(ctx, -added_size))
        return ENCAPSULATION_FAILED;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    outer_ethernet = data;
    outer_ipv4 = (void *)(outer_ethernet + 1);
    inner_ipv4 = (void *)(outer_ipv4 + 1);

    if ((void *)(inner_ipv4 + 1) > data_end) {
        *failure_action = XDP_DROP;
        return ENCAPSULATION_FAILED;
    }

    __builtin_memcpy(outer_ethernet->h_source, route->smac, ETH_ALEN);
    __builtin_memcpy(outer_ethernet->h_dest, route->dmac, ETH_ALEN);
    outer_ethernet->h_proto = bpf_htons(ETH_P_IP);

    build_outer_ipv4(outer_ipv4, outer_ip_size, device->ip_address, backend->address);

    return ENCAPSULATION_SUCCESS;
}

static __always_inline int redirect_packet(const struct bpf_fib_lookup *route)
{
    return bpf_redirect(route->ifindex, 0);
}

/* -------------------------- Load-balancer flow ----------------------- */

SEC("xdp")
int xdp_lb_main(struct xdp_md *ctx)
{
    struct vip_key vip_key = {};
    struct flow_key flow = {};
    struct device_config *device;
    struct vip_value *vip;
    struct backend *backend;
    struct backend fragment_backend = {};
    struct bpf_fib_lookup route = {};
    struct iphdr *ipv4 = NULL;
    __u32 device_ip_key = DEVICE_IP_KEY;
    int failure_action;
    int parse_result;

    device = bpf_map_lookup_elem(&device_ip_map, &device_ip_key);
    if (!device || !device->ip_address)
        return XDP_PASS;

    parse_result = parse_client_packet(ctx, &vip_key, &flow, &ipv4);
    if (parse_result == PARSE_RESULT_UNSUPPORTED)
        return XDP_PASS;

    if (parse_result != 0 && !device->fragment_handling_enabled)
        return XDP_PASS;

    if (parse_result == PARSE_RESULT_FRAGMENT_LATER) {
        struct frag_key key = {};
        int fragment_result;

        parse_fragment_key(ipv4, &key);
        fragment_result = handle_later_fragment(&key, &fragment_backend);
        if (fragment_result != FRAGMENT_RESULT_FOUND)
            return XDP_PASS;

        backend = &fragment_backend;
    } else {
        vip = bpf_map_lookup_elem(&vip_map, &vip_key);
        if (!vip)
            return XDP_PASS;

        backend = select_backend(&vip_key, vip, &flow);
        if (!backend)
            return XDP_PASS;

        if (parse_result == PARSE_RESULT_FRAGMENT_FIRST) {
            struct frag_key key = {};
            int fragment_result;

            parse_fragment_key(ipv4, &key);
            fragment_result = handle_first_fragment(&key, &flow, backend->address, &fragment_backend);
            if (fragment_result == FRAGMENT_RESULT_DROP)
                return XDP_DROP;
            if (fragment_result != FRAGMENT_RESULT_FOUND)
                return XDP_PASS;

            backend = &fragment_backend;
        }
    }

    if (encapsulate_packet(ctx, device, backend, &route, &failure_action) == ENCAPSULATION_FAILED)
        return failure_action;

    return redirect_packet(&route);
}

char _license[] SEC("license") = "GPL";
