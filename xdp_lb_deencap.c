#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETHERIP_PROTOCOL 97

SEC("xdp")
int xdp_lb_deencap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *outer_ethernet_header = data;
    struct iphdr *outer_ipv4_header;
    __u8 outer_header_length;
    __u16 outer_total_length;

    if ((void *)(outer_ethernet_header + 1) > data_end)
        return XDP_PASS;

    if (outer_ethernet_header->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    outer_ipv4_header = (void *)(outer_ethernet_header + 1);
    if ((void *)(outer_ipv4_header + 1) > data_end)
        return XDP_PASS;

    outer_header_length = outer_ipv4_header->ihl * 4;
    outer_total_length = bpf_ntohs(outer_ipv4_header->tot_len);

    if (outer_ipv4_header->version != 4 ||
        outer_header_length < sizeof(*outer_ipv4_header) ||
        outer_total_length < outer_header_length ||
        outer_ipv4_header->protocol != ETHERIP_PROTOCOL ||
        (void *)outer_ipv4_header + outer_header_length + sizeof(struct ethhdr) >
            data_end)
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, sizeof(struct ethhdr) + outer_header_length))
        return XDP_PASS;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
