#ifndef XDP_LB_VIP_RANGE_H
#define XDP_LB_VIP_RANGE_H

#include "xdp_lb_conf.h"

/* UDP VIPs first_vip, first_vip + 1, ... with one backend each, taken in turn. */
static int apply_vip_range(const char *first_vip, __u16 port, int vip_count,
                           const char *const *backends, int backend_count)
{
    static char addresses[MAX_VIPS][INET_ADDRSTRLEN];
    static struct service services[MAX_VIPS];

    for (int index = 0; index < vip_count; index++) {
        struct in_addr address = { htonl(ntohl(inet_addr(first_vip)) + index) };

        inet_ntop(AF_INET, &address, addresses[index], INET_ADDRSTRLEN);
        services[index] = (struct service){
            .vip = addresses[index],
            .port = port,
            .protocol = "udp",
            .backends = { backends[index % backend_count] },
        };
    }
    return apply_conf(services, vip_count, 0, 0);
}

#endif
