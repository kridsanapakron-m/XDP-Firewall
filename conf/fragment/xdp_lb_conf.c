#include "xdp_lb_conf.h"

#define VIP "192.168.100.100"
#define BACKENDS { "192.168.201.2", "192.168.202.2", "192.168.203.2" }

static const int fragment_handling = 1;
static const int icmp_pmtu = 0;

static const struct service services[] = {
    { VIP, 8080, "tcp", BACKENDS },
    { VIP, 8080, "udp", BACKENDS },
    { VIP, 8081, "udp", BACKENDS },
    { VIP, 5001, "tcp", BACKENDS },
};

int main(void)
{
    return apply_conf(services, ARRAY_SIZE(services), fragment_handling, icmp_pmtu);
}
