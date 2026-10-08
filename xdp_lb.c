#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "xdp_lb_common.h"

#define IPV4_FAMILY 2
#define DEFAULT_TTL 64
#define IPV4_DF 0x4000
#define IPV4_MF 0x2000
#define IPV4_FRAG_OFFSET_MASK 0x1fff

#define PMTU_REPLIES_PER_SECOND 25
#define ONE_SECOND_NS 1000000000ULL
#define IPV4_MINIMUM_MTU 68

#define ICMP_QUOTED_BYTES (sizeof(struct iphdr) + 8)
#define ICMP_REPLY_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
                         sizeof(struct icmphdr) + ICMP_QUOTED_BYTES)

enum packet_kind {
    PACKET_UNSUPPORTED,
    PACKET_WHOLE,
    PACKET_FIRST_FRAGMENT,
    PACKET_LATER_FRAGMENT,
};

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
    __uint(max_entries, MAX_VIPS);
    __type(key, struct vip_key);
    __type(value, struct vip_value);
} vip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BACKEND_SLOTS);
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VIPS);
    __type(key, struct vip_key);
    __type(value, struct awfd_classes);
} awfd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, AWFD_CONN_MAX_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct backend);
} conn_map SEC(".maps");

static __always_inline enum packet_kind
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
        return PACKET_UNSUPPORTED;

    ipv4 = (void *)(ethernet + 1);
    if ((void *)(ipv4 + 1) > data_end)
        return PACKET_UNSUPPORTED;

    ipv4_length = ipv4->ihl * 4;
    total_length = bpf_ntohs(ipv4->tot_len);
    if (ipv4->version != 4 ||
        ipv4_length < sizeof(*ipv4) ||
        total_length < ipv4_length ||
        total_length > (__u32)(data_end - (void *)ipv4))
        return PACKET_UNSUPPORTED;

    *out_ipv4 = ipv4;

    frag_off = bpf_ntohs(ipv4->frag_off);
    if (frag_off & IPV4_FRAG_OFFSET_MASK)
        return PACKET_LATER_FRAGMENT;

    if (ipv4->protocol != IPPROTO_TCP && ipv4->protocol != IPPROTO_UDP)
        return PACKET_UNSUPPORTED;

    ports = (void *)ipv4 + ipv4_length;
    if (ipv4_length + sizeof(*ports) > total_length || (void *)(ports + 1) > data_end)
        return PACKET_UNSUPPORTED;

    flow->source_address = ipv4->saddr;
    flow->destination_address = ipv4->daddr;
    flow->source_port = ports->source;
    flow->destination_port = ports->destination;
    flow->protocol = ipv4->protocol;

    return (frag_off & IPV4_MF) ? PACKET_FIRST_FRAGMENT : PACKET_WHOLE;
}

static __always_inline __u32 fnv1a_flow_hash(const struct flow_key *flow)
{
    __u32 words[] = {
        flow->source_address,
        flow->destination_address,
        ((__u32)flow->source_port << 16) | flow->destination_port,
        flow->protocol,
    };
    __u32 hash = 2166136261u;

    for (int i = 0; i < 4; i++)
        hash = (hash ^ words[i]) * 16777619u;
    return hash;
}

static __always_inline __u32 fmix32(__u32 hash)
{
    hash ^= hash >> 16;
    hash *= 0x85ebca6bu;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35u;
    hash ^= hash >> 16;
    return hash;
}

static __always_inline __be32 find_backend(const struct flow_key *flow)
{
    struct backend_key key = {
        .vip = {
            .address = flow->destination_address,
            .port = flow->destination_port,
            .protocol = flow->protocol,
        },
    };
    struct vip_value *vip;
    struct backend *backend;
    __u32 backend_count;

    vip = bpf_map_lookup_elem(&vip_map, &key.vip);
    if (!vip)
        return 0;

    backend_count = vip->backend_count;
    if (backend_count == 0 || backend_count > MAX_BACKENDS_PER_VIP)
        return 0;

    key.slot = fnv1a_flow_hash(flow) % backend_count;
    backend = bpf_map_lookup_elem(&backend_map, &key);
    return backend ? backend->address : 0;
}

static __always_inline __be32 awfd(const struct flow_key *flow)
{
    struct backend_key key = {
        .vip = {
            .address = flow->destination_address,
            .port = flow->destination_port,
            .protocol = flow->protocol,
        },
    };
    struct awfd_classes *classes;
    struct vip_value *vip;
    struct backend *backend;
    __u32 backend_count, stage1, stage2, point, class, size, index;

    vip = bpf_map_lookup_elem(&vip_map, &key.vip);
    if (!vip)
        return 0;
    backend_count = vip->backend_count;
    if (backend_count == 0 || backend_count > MAX_BACKENDS_PER_VIP)
        return 0;

    backend = bpf_map_lookup_elem(&conn_map, flow);
    if (backend)
        return backend->address;

    stage1 = fmix32(fnv1a_flow_hash(flow));
    stage2 = fmix32(stage1);
    key.slot = stage1 % backend_count;

    classes = bpf_map_lookup_elem(&awfd_map, &key.vip);
    if (classes && classes->weight_sum) {
        point = stage1 % classes->weight_sum;
        for (class = 0; class < AWFD_MAX_WEIGHT - 1; class++)
            if (point < classes->range_end[class])
                break;

        size = classes->class_size[class];
        if (size) {
            index = stage2 % size;
            barrier_var(index);

            if (index < MAX_BACKENDS_PER_VIP && classes->members[class][index] < backend_count)
                key.slot = classes->members[class][index];
        }
    }

    backend = bpf_map_lookup_elem(&backend_map, &key);
    if (!backend)
        return 0;

    if (bpf_map_update_elem(&conn_map, flow, backend, BPF_NOEXIST)) {
        struct backend *first = bpf_map_lookup_elem(&conn_map, flow);

        if (first)
            return first->address;
    }
    return backend->address;
}

static __always_inline struct frag_key frag_key_of(const struct iphdr *ipv4)
{
    return (struct frag_key){
        .source_address = ipv4->saddr,
        .destination_address = ipv4->daddr,
        .identification = ipv4->id,
        .protocol = ipv4->protocol,
    };
}

static __always_inline int frag_remember(const struct iphdr *ipv4,
                                         __be32 backend_address)
{
    struct frag_key key = frag_key_of(ipv4);
    struct frag_entry entry = {
        .backend_address = backend_address,
        .expires_at_ns = bpf_ktime_get_ns() + FRAG_TIMEOUT_NS,
    };

    return bpf_map_update_elem(&frag_cache_map, &key, &entry, BPF_ANY);
}

static __always_inline __be32 frag_backend(const struct iphdr *ipv4)
{
    struct frag_key key = frag_key_of(ipv4);
    struct frag_entry *entry = bpf_map_lookup_elem(&frag_cache_map, &key);

    if (!entry || entry->expires_at_ns <= bpf_ktime_get_ns())
        return 0;
    return entry->backend_address;
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
    *ipv4 = (struct iphdr){
        .version = 4,
        .ihl = sizeof(*ipv4) / 4,
        .tot_len = bpf_htons(total_length),
        .frag_off = bpf_htons(IPV4_DF),
        .ttl = DEFAULT_TTL,
        .protocol = protocol,
        .saddr = source,
        .daddr = destination,
    };
    ipv4->check = checksum16(ipv4, sizeof(*ipv4));
}

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
    struct pmtu_state *state = bpf_map_lookup_elem(&pmtu_state_map, &(__u32){0});
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
    __u32 outer_ip_size = sizeof(struct iphdr) + bpf_ntohs(inner_ipv4->tot_len);
    struct bpf_fib_lookup route = {
        .family = IPV4_FAMILY,
        .l4_protocol = IPPROTO_IPIP,
        .tot_len = outer_ip_size,
        .ifindex = ctx->ingress_ifindex,
        .ipv4_src = device->ip_address,
        .ipv4_dst = backend_address,
    };
    void *data;
    void *data_end;
    struct ethhdr *outer_ethernet;
    struct iphdr *outer_ipv4;
    int fib_result;

    if (outer_ip_size > 0xffff)
        return XDP_PASS;

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
    __be32 backend_address;
    enum packet_kind kind;

    device = bpf_map_lookup_elem(&device_ip_map, &(__u32){0});
    if (!device || !device->ip_address)
        return XDP_PASS;

    kind = parse_client_packet(ctx, &flow, &ipv4);
    if (kind == PACKET_UNSUPPORTED)
        return XDP_PASS;

    if (kind != PACKET_WHOLE && !device->fragment_handling_enabled)
        return XDP_PASS;

    if (kind == PACKET_LATER_FRAGMENT)
        backend_address = frag_backend(ipv4);
    else
        backend_address = awfd(&flow);
    if (!backend_address)
        return XDP_PASS;

    if (kind == PACKET_FIRST_FRAGMENT &&
        frag_remember(ipv4, backend_address))
        return XDP_PASS;

    return encapsulate_and_redirect(ctx, device, ipv4, backend_address);
}

char _license[] SEC("license") = "GPL";
