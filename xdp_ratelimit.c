#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h> 
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define THRESHOLD        250           // Max packets per second
#define TIME_WINDOW_NS   1000000000ULL // 1 วินาที (หน่วย: นาโนวินาที)
#define BLOCK_DURATION_NS 60000000000ULL // 60 วินาที
#define HONEYPOT_IP      0xC0A8B89A    // IP ของ honeypot (192.168.184.154)

static const unsigned char honeypot_mac[6] = {0x00, 0x0c, 0x29, 0x01, 0xa3, 0x6e}; // MAC ของ honeypot
static const unsigned char firewall_mac[6] = {0x00, 0x0c, 0x29, 0xd3, 0x85, 0x9d}; // MAC ของเครื่องจริง

struct rate_limit_entry {
    __u64 last_update;   // Timestamp ของการอัปเดตล่าสุด
    __u64 blocked_until; // Timestamp ที่จะหมดการ block (0 = ไม่ได้ถูก block)
    __u32 packet_count;  // จำนวน packet ในช่วงเวลา
};

// Hash map สำหรับ track rate limit ของแต่ละ source IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);                  // Source IP
    __type(value, struct rate_limit_entry);
} rate_limit_map SEC(".maps");


static __always_inline __u16 update_checksum(__u16 old_csum, __be32 old_ip, __be32 new_ip) {
    __u32 csum = (~old_csum & 0xFFFF);
    
    // ลบค่า IP เดิมออก
    csum += (~old_ip >> 16) & 0xFFFF;
    csum += (~old_ip & 0xFFFF);
    
    // บวกค่า IP ใหม่เข้าไป
    csum += (new_ip >> 16) & 0xFFFF;
    csum += (new_ip & 0xFFFF);
    
    // ม้วนบิตที่ล้น
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    
    return ~csum;
}


SEC("xdp") int ddos_protection(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // รับเฉพาะ IP packet
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = __builtin_bswap32(iph->saddr);
    __u64 now    = bpf_ktime_get_ns();

    struct rate_limit_entry *entry = bpf_map_lookup_elem(&rate_limit_map, &src_ip);

    if (entry) {
        // ── ตรวจสอบว่ายังอยู่ในช่วง block อยู่ไหม ──
        if (entry->blocked_until && now < entry->blocked_until) {
            // bpf_printk("XDP: IP %x still blocked, routing to honeypot\n", src_ip);
            goto redirect_honeypot;
        }

        // ── หมด block แล้ว หรือไม่เคย block ──
        if (now - entry->last_update < TIME_WINDOW_NS) {
            // อยู่ใน time window เดิม
            entry->packet_count++;
            if (entry->packet_count > THRESHOLD) {
                // เกิน threshold → เริ่ม block
                entry->blocked_until = now + BLOCK_DURATION_NS;
                bpf_printk("XDP: Rate limit exceeded! IP %x sent to honeypot\n", src_ip);
                goto redirect_honeypot;
            }
        } else {
            entry->last_update   = now;
            entry->packet_count  = 1;
            entry->blocked_until = 0;
        }
    } else {
        struct rate_limit_entry new_entry;
        __builtin_memset(&new_entry, 0, sizeof(new_entry));
        new_entry.last_update   = now;
        new_entry.packet_count  = 1;
        new_entry.blocked_until = 0;
        if (bpf_map_update_elem(&rate_limit_map, &src_ip, &new_entry, BPF_ANY) != 0)
            return XDP_ABORTED;
    }

    return XDP_PASS;

redirect_honeypot:
    //สลับ MAC Address
    __builtin_memcpy(eth->h_dest, honeypot_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, firewall_mac, ETH_ALEN);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";