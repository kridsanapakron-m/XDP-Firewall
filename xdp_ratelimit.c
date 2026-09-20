#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ค่า limit ต่อ protocol  (24 bytes) */
struct proto_config {
    __u64 block_ns;
    __u64 window_ns;
    __u32 threshold;
    __u32 enabled;      
};

/* ค่ากลาง  (12 bytes) */
struct global_config {
    __u8 honeypot_mac[6];
    __u8 firewall_mac[6];
};

/* key ของ rate map  (8 bytes) */
struct flow_key {
    __u32 ip;          
    __u32 proto;
};

struct rate_entry {
    __u64 last_update;
    __u64 blocked_until;
    __u32 packet_count;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);            /* index = IP protocol number, 0 = default */
    __type(key, __u32);
    __type(value, struct proto_config);
} proto_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_config);
} global_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct rate_entry);
} rate_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} tx_port SEC(".maps");

SEC("xdp")
int ddos_protection(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)              return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))       return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)              return XDP_PASS;

    __u32 zero  = 0;
    __u32 proto = iph->protocol;

    /* ---- เลือก config ของ protocol default (index 0) ---- */
    struct proto_config *pc = bpf_map_lookup_elem(&proto_config_map, &proto);
    if (!pc || !pc->enabled) {
        pc = bpf_map_lookup_elem(&proto_config_map, &zero);
        if (!pc || !pc->enabled)                   return XDP_PASS;
    }
    if (pc->threshold == 0)                        return XDP_PASS;

    struct global_config *gc = bpf_map_lookup_elem(&global_config_map, &zero);
    if (!gc)                                       return XDP_PASS;

    
    struct flow_key key = {
        .ip    = __builtin_bswap32(iph->saddr),
        .proto = proto,
    };
    __u64 now = bpf_ktime_get_ns();

    struct rate_entry *e = bpf_map_lookup_elem(&rate_limit_map, &key);
    if (!e) {
        struct rate_entry ne = { .last_update = now, .blocked_until = 0, .packet_count = 1 };
        bpf_map_update_elem(&rate_limit_map, &key, &ne, BPF_ANY);
        return XDP_PASS;
    }

    if (e->blocked_until && now < e->blocked_until)
        goto redirect;

    if (now - e->last_update > pc->window_ns) {   /* window ใหม่ */
        e->last_update   = now;
        e->packet_count  = 1;
        e->blocked_until = 0;
        return XDP_PASS;
    }

    e->packet_count++;
    if (e->packet_count > pc->threshold) {
        e->blocked_until = now + pc->block_ns;
        goto redirect;
    }
    return XDP_PASS;

redirect:
    __builtin_memcpy(eth->h_dest,   gc->honeypot_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, gc->firewall_mac, ETH_ALEN);
    return bpf_redirect_map(&tx_port, 0, 0);
}

char _license[] SEC("license") = "GPL";