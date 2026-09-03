#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IPV4_FRAG_BITS (0x2000 | 0x1fff)

SEC("xdp")
int xdp_lb_deencap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *outer_ethernet_header = data;
    struct iphdr *outer_ipv4_header;
    struct iphdr *inner_ipv4_header;
    __u8 source_mac[ETH_ALEN];
    __u8 destination_mac[ETH_ALEN];
    __u8 outer_header_length;
    __u8 inner_header_length;
    __u16 outer_total_length;
    __u16 inner_total_length;
    __u32 available_length;

    if ((void *)(outer_ethernet_header + 1) > data_end)
        return XDP_PASS;

    if (outer_ethernet_header->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    outer_ipv4_header = (void *)(outer_ethernet_header + 1);
    if ((void *)(outer_ipv4_header + 1) > data_end)
        return XDP_PASS;

    outer_header_length = outer_ipv4_header->ihl * 4;
    outer_total_length = bpf_ntohs(outer_ipv4_header->tot_len);
    available_length = data_end - (void *)outer_ipv4_header;

    if (outer_ipv4_header->version != 4 ||
        outer_header_length < sizeof(*outer_ipv4_header) ||
        outer_total_length < outer_header_length + sizeof(struct iphdr) ||
        outer_total_length > available_length ||
        outer_ipv4_header->protocol != IPPROTO_IPIP ||
        bpf_ntohs(outer_ipv4_header->frag_off) & IPV4_FRAG_BITS)
        return XDP_PASS;

    inner_ipv4_header = (void *)outer_ipv4_header + outer_header_length;
    if ((void *)(inner_ipv4_header + 1) > data_end ||
        inner_ipv4_header->version != 4)
        return XDP_PASS;

    inner_header_length = inner_ipv4_header->ihl * 4;
    inner_total_length = bpf_ntohs(inner_ipv4_header->tot_len);

    if (inner_header_length < sizeof(*inner_ipv4_header) ||
        inner_total_length < inner_header_length ||
        inner_total_length > outer_total_length - outer_header_length)
        return XDP_PASS;

    __builtin_memcpy(source_mac, outer_ethernet_header->h_source, ETH_ALEN);
    __builtin_memcpy(destination_mac, outer_ethernet_header->h_dest, ETH_ALEN);

    /* Removing only outer IPv4 leaves room to rebuild Ethernet. */
    if (bpf_xdp_adjust_head(ctx, outer_header_length))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    outer_ethernet_header = data;
    inner_ipv4_header = (void *)(outer_ethernet_header + 1);

    if ((void *)(inner_ipv4_header + 1) > data_end)
        return XDP_DROP;

    __builtin_memcpy(outer_ethernet_header->h_source, source_mac, ETH_ALEN);
    __builtin_memcpy(outer_ethernet_header->h_dest, destination_mac, ETH_ALEN);
    outer_ethernet_header->h_proto = bpf_htons(ETH_P_IP);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
