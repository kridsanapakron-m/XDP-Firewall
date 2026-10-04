#include <linux/bpf.h>
#include <linux/icmp.h>
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
 *
 * Helpers that can end the packet's journey return an XDP action directly, so
 * XDP_PASS/XDP_DROP/XDP_TX/XDP_REDIRECT is the only result vocabulary they use.
 */

#define IPV4_FAMILY 2
#define DEFAULT_TTL 64
#define IPV4_DF 0x4000
#define IPV4_MF 0x2000
#define IPV4_FRAG_OFFSET_MASK 0x1fff
#define DEVICE_IP_KEY 0

#define PARSE_RESULT_UNSUPPORTED -1
#define PARSE_RESULT_OK 0
#define PARSE_RESULT_FRAGMENT_FIRST 1
#define PARSE_RESULT_FRAGMENT_LATER 2

#define ACTION_CONTINUE -1

#define PMTU_STATE_KEY 0
#define PMTU_REPLIES_PER_SECOND 25
#define ONE_SECOND_NS 1000000000ULL
#define IPV4_MINIMUM_MTU 68

#define ICMP_QUOTED_BYTES (sizeof(struct iphdr) + 8)
#define ICMP_REPLY_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
                         sizeof(struct icmphdr) + ICMP_QUOTED_BYTES)

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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pmtu_state);
} pmtu_state_map SEC(".maps");

static __always_inline int
parse_client_packet(struct xdp_md *ctx, struct flow_key *flow,
                    struct iphdr **out_ipv4)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *ethernet = data;
    struct iphdr *ipv4;
    struct layer4_ports *ports;
    __u32 ipv4_length;
    __u32 total_length;
    __u16 frag_off;

    if ((void *)(ethernet + 1) > data_end || ethernet->h_proto != bpf_htons(ETH_P_IP))
        return PARSE_RESULT_UNSUPPORTED;

    ipv4 = (void *)(ethernet + 1);
    if ((void *)(ipv4 + 1) > data_end)
        return PARSE_RESULT_UNSUPPORTED;

    ipv4_length = ipv4->ihl * 4;
    total_length = bpf_ntohs(ipv4->tot_len);
    if (ipv4->version != 4 ||
        ipv4_length < sizeof(*ipv4) ||
        total_length < ipv4_length ||
        total_length > (__u32)(data_end - (void *)ipv4))
        return PARSE_RESULT_UNSUPPORTED;

    *out_ipv4 = ipv4;

    frag_off = bpf_ntohs(ipv4->frag_off);
    if (frag_off & IPV4_FRAG_OFFSET_MASK)
        return PARSE_RESULT_FRAGMENT_LATER;

    if (ipv4->protocol != IPPROTO_TCP && ipv4->protocol != IPPROTO_UDP)
        return PARSE_RESULT_UNSUPPORTED;

    ports = (void *)ipv4 + ipv4_length;
    if (ipv4_length + sizeof(*ports) > total_length || (void *)(ports + 1) > data_end)
        return PARSE_RESULT_UNSUPPORTED;

    flow->source_address = ipv4->saddr;
    flow->destination_address = ipv4->daddr;
    flow->source_port = ports->source;
    flow->destination_port = ports->destination;
    flow->protocol = ipv4->protocol;

    return (frag_off & IPV4_MF) ? PARSE_RESULT_FRAGMENT_FIRST : PARSE_RESULT_OK;
}

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

static __always_inline __be32 find_backend(const struct flow_key *flow)
{
    struct vip_key vip_key = {
        .address = flow->destination_address,
        .port = flow->destination_port,
        .protocol = flow->protocol,
        .padding = 0,
    };
    struct backend_key backend_key = {};
    struct vip_value *vip;
    struct backend *backend;
    __u32 backend_count;

    vip = bpf_map_lookup_elem(&vip_map, &vip_key);
    if (!vip)
        return 0;

    backend_count = vip->backend_count;
    if (backend_count == 0 || backend_count > MAX_BACKENDS_PER_VIP)
        return 0;

    backend_key.vip = vip_key;
    backend_key.slot = flow_hash(flow) % backend_count;

    backend = bpf_map_lookup_elem(&backend_map, &backend_key);
    return backend ? backend->address : 0;
}

static __always_inline int
handle_fragment(const struct iphdr *ipv4, const struct flow_key *flow,
                __be32 *backend_address)
{
    struct frag_key key = {};
    struct frag_entry candidate = {};
    struct frag_entry *existing;
    __u64 now = bpf_ktime_get_ns();

    key.source_address = ipv4->saddr;
    key.destination_address = ipv4->daddr;
    key.identification = ipv4->id;
    key.protocol = ipv4->protocol;

    existing = bpf_map_lookup_elem(&frag_cache_map, &key);
    if (existing && existing->expires_at_ns > now) {
        if (flow &&
            (existing->source_port != flow->source_port ||
             existing->destination_port != flow->destination_port))
            return XDP_DROP;

        *backend_address = existing->backend_address;
        return ACTION_CONTINUE;
    }

    if (!flow)
        return XDP_PASS;

    candidate.backend_address = *backend_address;
    candidate.source_port = flow->source_port;
    candidate.destination_port = flow->destination_port;
    candidate.expires_at_ns = now + FRAG_TIMEOUT_NS;

    if (bpf_map_update_elem(&frag_cache_map, &key, &candidate, BPF_ANY))
        return XDP_PASS;

    return ACTION_CONTINUE;
}

static __always_inline __sum16 checksum16(const void *start, __u32 length)
{
    const __u16 *words = start;
    __u32 sum = 0;

    for (__u32 i = 0; i < length / sizeof(*words); i++)
        sum += words[i];

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static __always_inline void
build_ipv4_header(struct iphdr *ipv4, __u16 total_length, __u8 protocol,
                  __be32 source, __be32 destination)
{
    ipv4->version = 4;
    ipv4->ihl = sizeof(*ipv4) / 4;
    ipv4->tos = 0;
    ipv4->tot_len = bpf_htons(total_length);
    ipv4->id = 0;
    ipv4->frag_off = bpf_htons(IPV4_DF);
    ipv4->ttl = DEFAULT_TTL;
    ipv4->protocol = protocol;
    ipv4->saddr = source;
    ipv4->daddr = destination;
    ipv4->check = 0;
    ipv4->check = checksum16(ipv4, sizeof(*ipv4));
}

/*
 * Rewrites the oversized packet in place: its IPv4 header + 8 bytes are copied
 * to where the reply quotes them, the headers in front are rebuilt, and the
 * tail is trimmed off.
 */
static __always_inline int build_pmtu_reply(struct xdp_md *ctx, __u16 route_mtu)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *ethernet = data;
    struct iphdr *ipv4 = (void *)(ethernet + 1);
    struct icmphdr *icmp = (void *)(ipv4 + 1);
    struct iphdr *quoted = (void *)(icmp + 1);
    __u8 client_mac[ETH_ALEN];

    if (data + ICMP_REPLY_SIZE > data_end ||
        ipv4->ihl != sizeof(*ipv4) / 4 ||
        route_mtu < IPV4_MINIMUM_MTU + sizeof(*ipv4))
        return XDP_PASS;

    __builtin_memcpy(quoted, ipv4, ICMP_QUOTED_BYTES);

    __builtin_memcpy(client_mac, ethernet->h_source, ETH_ALEN);
    __builtin_memcpy(ethernet->h_source, ethernet->h_dest, ETH_ALEN);
    __builtin_memcpy(ethernet->h_dest, client_mac, ETH_ALEN);

    build_ipv4_header(ipv4, ICMP_REPLY_SIZE - sizeof(*ethernet), IPPROTO_ICMP,
                      quoted->daddr, quoted->saddr);

    *icmp = (struct icmphdr){
        .type = ICMP_DEST_UNREACH,
        .code = ICMP_FRAG_NEEDED,
        .un.frag.mtu = bpf_htons((__u16)(route_mtu - sizeof(*ipv4))),
    };
    icmp->checksum = checksum16(icmp, sizeof(*icmp) + ICMP_QUOTED_BYTES);

    if (bpf_xdp_adjust_tail(ctx, ICMP_REPLY_SIZE - (int)(data_end - data)))
        return XDP_DROP;
    return XDP_TX;
}

static __always_inline int pmtu_reply_allowed(struct pmtu_state *state)
{
    __u64 now = bpf_ktime_get_ns();

    if (now - state->window_start_ns >= ONE_SECOND_NS) {
        state->window_start_ns = now;
        state->window_count = 0;
    }

    if (state->window_count >= PMTU_REPLIES_PER_SECOND)
        return 0;

    state->window_count++;
    return 1;
}

static __always_inline int
handle_fragmentation_needed(struct xdp_md *ctx, const struct device_config *device,
                            const struct iphdr *inner_ipv4, __u16 route_mtu)
{
    __u32 state_key = PMTU_STATE_KEY;
    struct pmtu_state *state = bpf_map_lookup_elem(&pmtu_state_map, &state_key);
    int action;

    if (!state)
        return XDP_PASS;

    state->frag_needed++;
    if (!device->icmp_pmtu_enabled ||
        !(inner_ipv4->frag_off & bpf_htons(IPV4_DF)) ||
        !pmtu_reply_allowed(state))
        return XDP_PASS;

    action = build_pmtu_reply(ctx, route_mtu);
    if (action == XDP_TX)
        state->icmp_sent++;
    return action;
}

static __always_inline int
encapsulate_and_redirect(struct xdp_md *ctx, const struct device_config *device,
                         const struct iphdr *inner_ipv4, __be32 backend_address)
{
    struct bpf_fib_lookup route = {};
    void *data;
    void *data_end;
    struct ethhdr *outer_ethernet;
    struct iphdr *outer_ipv4;
    __u32 inner_size;
    __u32 outer_ip_size;
    int fib_result;

    inner_size = bpf_ntohs(inner_ipv4->tot_len);
    if (inner_size > 0xffff - sizeof(struct iphdr))
        return XDP_PASS;
    outer_ip_size = sizeof(struct iphdr) + inner_size;

    route.family = IPV4_FAMILY;
    route.ifindex = ctx->ingress_ifindex;
    route.l4_protocol = IPPROTO_IPIP;
    route.tot_len = outer_ip_size;
    route.ipv4_src = device->ip_address;
    route.ipv4_dst = backend_address;

    fib_result = bpf_fib_lookup(ctx, &route, sizeof(route), 0);
    if (fib_result == BPF_FIB_LKUP_RET_FRAG_NEEDED)
        return handle_fragmentation_needed(ctx, device, inner_ipv4,
                                           route.mtu_result);
    if (fib_result != BPF_FIB_LKUP_RET_SUCCESS)
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct iphdr)))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    outer_ethernet = data;
    outer_ipv4 = (void *)(outer_ethernet + 1);

    if ((void *)(outer_ipv4 + 1) > data_end)
        return XDP_DROP;

    __builtin_memcpy(outer_ethernet->h_source, route.smac, ETH_ALEN);
    __builtin_memcpy(outer_ethernet->h_dest, route.dmac, ETH_ALEN);
    outer_ethernet->h_proto = bpf_htons(ETH_P_IP);

    build_ipv4_header(outer_ipv4, outer_ip_size, IPPROTO_IPIP,
                      device->ip_address, backend_address);

    return bpf_redirect(route.ifindex, 0);
}

SEC("xdp")
int xdp_lb_main(struct xdp_md *ctx)
{
    struct flow_key flow = {};
    struct device_config *device;
    struct iphdr *ipv4 = NULL;
    __be32 backend_address = 0;
    __u32 device_ip_key = DEVICE_IP_KEY;
    int parse_result;
    int action;

    device = bpf_map_lookup_elem(&device_ip_map, &device_ip_key);
    if (!device || !device->ip_address)
        return XDP_PASS;

    parse_result = parse_client_packet(ctx, &flow, &ipv4);
    if (parse_result == PARSE_RESULT_UNSUPPORTED)
        return XDP_PASS;

    if (parse_result != PARSE_RESULT_OK && !device->fragment_handling_enabled)
        return XDP_PASS;

    if (parse_result == PARSE_RESULT_FRAGMENT_LATER) {
        action = handle_fragment(ipv4, NULL, &backend_address);
    } else {
        backend_address = find_backend(&flow);
        if (!backend_address)
            return XDP_PASS;

        action = ACTION_CONTINUE;
        if (parse_result == PARSE_RESULT_FRAGMENT_FIRST)
            action = handle_fragment(ipv4, &flow, &backend_address);
    }

    if (action != ACTION_CONTINUE)
        return action;

    return encapsulate_and_redirect(ctx, device, ipv4, backend_address);
}

char _license[] SEC("license") = "GPL";
