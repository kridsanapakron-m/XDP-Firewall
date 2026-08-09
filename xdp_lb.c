#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IPV4_MF 0x2000
#define IPV4_OFFSET 0x1fff

SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    __u16 frag_off;
    __u8 ip_header_len;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    ip_header_len = iph->ihl * 4;
    if (iph->version != 4 || ip_header_len < sizeof(*iph))
        return XDP_PASS;

    if ((void *)iph + ip_header_len > data_end)
        return XDP_PASS;

    frag_off = bpf_ntohs(iph->frag_off);
    if (frag_off & (IPV4_MF | IPV4_OFFSET))
        return XDP_PASS;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)iph + ip_header_len;

        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        return XDP_PASS;
    }

    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)iph + ip_header_len;

        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
