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
#define MAX_B_SERVERS_PER_VIP 64

struct vip_key {
    __be32 address;
    __be16 port;
    __u8 protocol;
    __u8 padding;
};

struct vip_config {
    __u32 b_server_count;
};

struct b_server_key {
    struct vip_key vip;
    __u32 slot;
};

struct b_server {
    __be32 address;
    __be16 port;
    __u8 mac_address[ETH_ALEN];
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
    __type(key, struct b_server_key);
    __type(value, struct b_server);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} b_server_map SEC(".maps");

static __always_inline __u32
b_server_hash(__be32 source_address, __be32 destination_address,
              __be16 source_port, __be16 destination_port, __u8 protocol)
{
    const __u32 fnv1a_offset_basis = 2166136261u;
    const __u32 fnv1a_prime = 16777619u;
    __u32 hash = fnv1a_offset_basis;

    hash ^= source_address;
    hash *= fnv1a_prime;

    hash ^= destination_address;
    hash *= fnv1a_prime;

    hash ^= ((__u32)source_port << 16) | destination_port;
    hash *= fnv1a_prime;

    hash ^= protocol;
    hash *= fnv1a_prime;

    return hash;
}

static __always_inline __sum16 fold_checksum(__u32 checksum)
{
    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum & 0xffff) + (checksum >> 16);
    return ~checksum;
}

static __always_inline __sum16 update_checksum_32(__sum16 old_checksum,
                                                   __be32 old_value,
                                                   __be32 new_value)
{
    __u32 checksum = ~((__u32)old_checksum) & 0xffff;

    checksum = bpf_csum_diff(&old_value, sizeof(old_value),
                             &new_value, sizeof(new_value), checksum);
    return fold_checksum(checksum);
}

static __always_inline __attribute__((unused)) void
rewrite_destination_ip(struct iphdr *ipv4_header, void *transport_header,
                       __be32 new_destination_address)
{
    __be32 old_destination_address = ipv4_header->daddr;

    ipv4_header->check = update_checksum_32(ipv4_header->check,
                                            old_destination_address,
                                            new_destination_address);

    if (ipv4_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = transport_header;

        tcp_header->check = update_checksum_32(tcp_header->check,
                                               old_destination_address,
                                               new_destination_address);
    } else if (ipv4_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = transport_header;

        if (udp_header->check)
            udp_header->check = update_checksum_32(udp_header->check,
                                                   old_destination_address,
                                                   new_destination_address);
    }

    ipv4_header->daddr = new_destination_address;
}

static __always_inline void
rewrite_destination_mac(struct ethhdr *ethernet_header,
                        const __u8 new_destination_mac[ETH_ALEN])
{
    __builtin_memcpy(ethernet_header->h_dest, new_destination_mac, ETH_ALEN);
}

SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *ethernet_header = data;
    struct iphdr *ipv4_header;
    __u16 fragment_offset;
    __u8 ipv4_header_length;
    struct vip_key vip = {};
    struct vip_config *vip_config;
    struct b_server_key b_server_key = {};
    struct b_server *selected_b_server;
    __u16 source_port;
    __u16 destination_port;
    __u32 flow_hash;

    if ((void *)(ethernet_header + 1) > data_end)
        return XDP_PASS;

    if (ethernet_header->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    ipv4_header = (void *)(ethernet_header + 1);
    if ((void *)(ipv4_header + 1) > data_end)
        return XDP_PASS;

    ipv4_header_length = ipv4_header->ihl * 4;
    if (ipv4_header->version != 4 ||
        ipv4_header_length < sizeof(*ipv4_header))
        return XDP_PASS;

    if ((void *)ipv4_header + ipv4_header_length > data_end)
        return XDP_PASS;

    fragment_offset = bpf_ntohs(ipv4_header->frag_off);
    if (fragment_offset &
        (IPV4_MORE_FRAGMENTS_FLAG | IPV4_FRAGMENT_OFFSET_MASK))
        return XDP_PASS;

    if (ipv4_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (void *)ipv4_header + ipv4_header_length;

        if ((void *)(tcp_header + 1) > data_end)
            return XDP_PASS;

        source_port = tcp_header->source;
        destination_port = tcp_header->dest;
    } else if (ipv4_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (void *)ipv4_header + ipv4_header_length;

        if ((void *)(udp_header + 1) > data_end)
            return XDP_PASS;

        source_port = udp_header->source;
        destination_port = udp_header->dest;
    } else {
        return XDP_PASS;
    }

    vip.address = ipv4_header->daddr;
    vip.port = destination_port;
    vip.protocol = ipv4_header->protocol;

    vip_config = bpf_map_lookup_elem(&vip_map, &vip);
    if (!vip_config || vip_config->b_server_count == 0 ||
        vip_config->b_server_count > MAX_B_SERVERS_PER_VIP)
        return XDP_PASS;

    flow_hash = b_server_hash(ipv4_header->saddr, ipv4_header->daddr,
                              source_port, destination_port,
                              ipv4_header->protocol);
    b_server_key.vip = vip;
    b_server_key.slot = flow_hash % vip_config->b_server_count;

    selected_b_server = bpf_map_lookup_elem(&b_server_map, &b_server_key);
    if (!selected_b_server)
        return XDP_PASS;

    rewrite_destination_mac(ethernet_header,
                            selected_b_server->mac_address);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
