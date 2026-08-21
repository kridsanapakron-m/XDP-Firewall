#ifndef XDP_LB_COMMON_H
#define XDP_LB_COMMON_H

#include <linux/if_ether.h>
#include <linux/types.h>

#define MAX_BACKENDS_PER_VIP 64

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
    __u8 mac[ETH_ALEN];
    __u8 padding[2];
};

struct device_config {
    __be32 ip_address;
};

#endif
