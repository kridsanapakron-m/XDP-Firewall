#ifndef XDP_LB_COMMON_H
#define XDP_LB_COMMON_H

#include <linux/types.h>

#define MAX_VIPS 1024
#define MAX_BACKENDS_PER_VIP 64
#define MAX_BACKEND_SLOTS (MAX_VIPS * MAX_BACKENDS_PER_VIP)

/* Fragment cache: fixed size, LRU-evicted automatically when full. */
#define FRAG_CACHE_MAX_ENTRIES 65536
#define FRAG_TIMEOUT_NS (30ULL * 1000000000ULL)

/* Types below are the shared ABI of the pinned BPF maps. */
struct vip_key {
    __be32 address;
    __be16 port;
    __u8 protocol;
    __u8 padding;
};

struct vip_value {
    __u32 backend_count;
};

struct backend_key {
    struct vip_key vip;
    __u32 slot;
};

struct backend {
    __be32 address;
};

struct device_config {
    __be32 ip_address;
    __u32 fragment_handling_enabled;
    __u32 icmp_pmtu_enabled;
};

/* Per-CPU rate-limit window and counters for ICMP "fragmentation needed". */
struct pmtu_state {
    __u64 window_start_ns;
    __u32 window_count;
    __u32 frag_needed;
    __u32 icmp_sent;
    __u32 padding;
};

/* Datagram identity for a fragment; values come from the original IPv4 header. */
struct frag_key {
    __be32 source_address;
    __be32 destination_address;
    __be16 identification;
    __u8 protocol;
    __u8 padding;
};

/* Cached result of backend selection made for the first fragment. */
struct frag_entry {
    __be32 backend_address;
    __u32 padding;
    __u64 expires_at_ns;
};

#endif
