#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IPV4_MORE_FRAGMENTS_FLAG 0x2000
#define IPV4_FRAGMENT_OFFSET_MASK 0x1fff
#define IPV4_DONT_FRAGMENT_FLAG 0x4000
#define IPV4_ADDRESS_FAMILY 2
#define DEFAULT_TUNNEL_TTL 64
#define ETHERIP_PROTOCOL 97
#define TUNNEL_CONFIG_KEY 0
#define MAX_SERVERS_PER_VIP 64

struct vip_key {
    __be32 address;
    __be16 port;
    __u8 protocol;
    __u8 padding;
};

struct vip_config {
    __u32 server_count;
};

struct server_key {
    struct vip_key vip;
    __u32 slot;
};

struct server {
    __be32 address;
    __u8 mac_address[ETH_ALEN];
};

struct tunnel_config {
    __be32 source_address;
};

struct flow_info {
    struct ethhdr *eth;
    struct iphdr *ip;
    __be32 source_address;
    __be32 destination_address;
    __be16 source_port;
    __be16 destination_port;
    __u8 protocol;
};

struct transport_ports {
    __be16 source;
    __be16 destination;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct vip_key);
    __type(value, struct vip_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} vip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct server_key);
    __type(value, struct server);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} server_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tunnel_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tunnel_config_map SEC(".maps");

/* Keep packets from the same 5-tuple on the same server. */
static __always_inline __u32 flow_hash(const struct flow_info *flow)
{
    const __u32 fnv1a_offset_basis = 2166136261u;
    const __u32 fnv1a_prime = 16777619u;
    __u32 hash = fnv1a_offset_basis;

    hash ^= flow->source_address;
    hash *= fnv1a_prime;

    hash ^= flow->destination_address;
    hash *= fnv1a_prime;

    hash ^= ((__u32)flow->source_port << 16) | flow->destination_port;
    hash *= fnv1a_prime;

    hash ^= flow->protocol;
    hash *= fnv1a_prime;

    return hash;
}

static __always_inline __sum16 fold_checksum(__u32 checksum)
{
    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum & 0xffff) + (checksum >> 16);
    return ~checksum;
}

static __always_inline __sum16 ipv4_header_checksum(struct iphdr *ip)
{
    __u32 checksum = 0;
    __u16 *word = (__u16 *)ip;

    ip->check = 0;

#pragma clang loop unroll(full)
    for (__u32 i = 0; i < sizeof(*ip) / sizeof(*word); i++)
        checksum += word[i];

    return fold_checksum(checksum);
}

static __always_inline int parse_flow(struct xdp_md *ctx,
                                      struct flow_info *flow)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    __u8 ip_header_length = ip->ihl * 4;
    if (ip->version != 4 || ip_header_length < sizeof(*ip))
        return -1;

    if ((void *)ip + ip_header_length > data_end)
        return -1;

    __u16 fragment_offset = bpf_ntohs(ip->frag_off);
    if (fragment_offset &
        (IPV4_MORE_FRAGMENTS_FLAG | IPV4_FRAGMENT_OFFSET_MASK))
        return -1;

    void *transport_header = (void *)ip + ip_header_length;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport_header;

        if ((void *)(tcp + 1) > data_end)
            return -1;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport_header;

        if ((void *)(udp + 1) > data_end)
            return -1;
    } else {
        return -1;
    }

    struct transport_ports *ports = transport_header;

    flow->eth = eth;
    flow->ip = ip;
    flow->source_address = ip->saddr;
    flow->destination_address = ip->daddr;
    flow->source_port = ports->source;
    flow->destination_port = ports->destination;
    flow->protocol = ip->protocol;

    return 0;
}

static __always_inline struct vip_config *
lookup_vip(const struct flow_info *flow, struct vip_key *vip)
{
    vip->address = flow->destination_address;
    vip->port = flow->destination_port;
    vip->protocol = flow->protocol;

    struct vip_config *config = bpf_map_lookup_elem(&vip_map, vip);

    if (!config || config->server_count == 0 ||
        config->server_count > MAX_SERVERS_PER_VIP)
        return 0;

    return config;
}

static __always_inline struct server *
select_server(const struct flow_info *flow, const struct vip_key *vip,
              const struct vip_config *config)
{
    struct server_key key = {
        .vip = *vip,
        .slot = flow_hash(flow) % config->server_count,
    };

    return bpf_map_lookup_elem(&server_map, &key);
}

static __always_inline struct tunnel_config *get_tunnel_config(void)
{
    __u32 key = TUNNEL_CONFIG_KEY;
    struct tunnel_config *config =
        bpf_map_lookup_elem(&tunnel_config_map, &key);

    if (!config || !config->source_address)
        return 0;

    return config;
}

static __always_inline void
build_outer_ipv4_header(struct iphdr *outer_ip, __u32 total_length,
                        __be32 source_address, __be32 destination_address)
{
    outer_ip->version = 4;
    outer_ip->ihl = sizeof(*outer_ip) / 4;
    outer_ip->tos = 0;
    outer_ip->tot_len = bpf_htons(total_length);
    outer_ip->id = 0;
    outer_ip->frag_off = bpf_htons(IPV4_DONT_FRAGMENT_FLAG);
    outer_ip->ttl = DEFAULT_TUNNEL_TTL;
    outer_ip->protocol = ETHERIP_PROTOCOL;
    outer_ip->saddr = source_address;
    outer_ip->daddr = destination_address;
    outer_ip->check = ipv4_header_checksum(outer_ip);
}

static __always_inline int
encapsulate_and_redirect(struct xdp_md *ctx,
                         const struct tunnel_config *tunnel,
                         const struct server *server)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 inner_length = data_end - data;
    __u32 outer_length = inner_length + sizeof(struct iphdr);

    if (inner_length < sizeof(struct ethhdr) + sizeof(struct iphdr) ||
        outer_length > 0xffff)
        return XDP_PASS;

    struct bpf_fib_lookup route = {
        .family = IPV4_ADDRESS_FAMILY,
        .ifindex = ctx->ingress_ifindex,
        .l4_protocol = ETHERIP_PROTOCOL,
        .tot_len = outer_length,
        .ipv4_src = tunnel->source_address,
        .ipv4_dst = server->address,
    };

    int fib_result = bpf_fib_lookup(ctx, &route, sizeof(route),
                                    BPF_FIB_LOOKUP_OUTPUT);

    /* Neighbor discovery must be handled by the control plane. */
    if (fib_result == BPF_FIB_LKUP_RET_NO_NEIGH)
        return XDP_PASS;

    if (fib_result != BPF_FIB_LKUP_RET_SUCCESS)
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, 0 -
                            (int)(sizeof(struct ethhdr) +
                                  sizeof(struct iphdr))))
        return XDP_PASS;

    /* Packet memory may have moved, so reload all data pointers. */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *outer_eth = data;
    struct iphdr *outer_ip = (void *)(outer_eth + 1);
    struct ethhdr *inner_eth = data + sizeof(struct ethhdr) +
                              sizeof(struct iphdr);

    if ((void *)(outer_ip + 1) > data_end ||
        (void *)(inner_eth + 1) > data_end)
        return XDP_DROP;

    __builtin_memcpy(outer_eth->h_source, route.smac, ETH_ALEN);
    __builtin_memcpy(outer_eth->h_dest, route.dmac, ETH_ALEN);
    outer_eth->h_proto = bpf_htons(ETH_P_IP);

    __builtin_memcpy(inner_eth->h_source, route.smac, ETH_ALEN);
    __builtin_memcpy(inner_eth->h_dest, server->mac_address, ETH_ALEN);

    build_outer_ipv4_header(outer_ip, outer_length,
                            tunnel->source_address, server->address);

    return bpf_redirect(route.ifindex, 0);
}

SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
    struct flow_info flow = {};

    if (parse_flow(ctx, &flow) < 0)
        return XDP_PASS;

    struct vip_key vip = {};
    struct vip_config *vip_config = lookup_vip(&flow, &vip);
    if (!vip_config)
        return XDP_PASS;

    struct server *server = select_server(&flow, &vip, vip_config);
    if (!server)
        return XDP_PASS;

    struct tunnel_config *tunnel = get_tunnel_config();
    if (!tunnel)
        return XDP_PASS;

    return encapsulate_and_redirect(ctx, tunnel, server);
}

char _license[] SEC("license") = "GPL";
