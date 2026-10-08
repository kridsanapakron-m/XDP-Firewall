#ifndef XDP_LB_AWFD_COMMON_H
#define XDP_LB_AWFD_COMMON_H

#include "xdp_lb_common.h"

/*
 * Shared ABI of AWFD, the flow dispatcher of Aghdai et al., "Spotlight"
 * (reseach/1806.08455v3.pdf). The daemon xdp_lb_awfd writes
 * awfd_map, and xdp_lb_agent answers the daemon's probes.
 */
#define AWFD_MAX_WEIGHT 16          /* upper bound of m; Figure 10 tests m up to 16 */
#define AWFD_CONN_MAX_ENTRIES 65536 /* connection table, LRU-evicted when full */
#define AWFD_AGENT_PORT 9900
#define AWFD_MILLI 1000             /* U and C travel as integers x1000 */

/*
 * Priority classes of one VIP (Figure 5). Index k - 1 holds class B_k; B_0 is
 * left out because it is never chosen (footnote 2). In Stage I, B_k owns
 * [range_end[k - 2], range_end[k - 1]), a range k * |B_k| long (eq. 1).
 */
struct awfd_classes {
    __u32 weight_sum;
    __u32 range_end[AWFD_MAX_WEIGHT];
    __u32 class_size[AWFD_MAX_WEIGHT];
    __u8 members[AWFD_MAX_WEIGHT][MAX_BACKENDS_PER_VIP]; /* backend_map slots */
};

/* Agent reply to a probe carrying `sequence`; all fields in network byte order. */
struct awfd_probe_reply {
    __be32 sequence;
    __be32 utilization_milli; /* U x 1000 */
    __be32 capacity_milli;    /* C x 1000, in CPUs */
};

#endif
