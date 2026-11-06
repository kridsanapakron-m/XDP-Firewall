#include "conf/vip_range.h"

static const char *first_vip = "10.100.0.1";
static const __u16 port = 8080;
static const int vip_count = 1;
static const char *const backends[] = { "192.168.201.2", "192.168.202.2", "192.168.203.2" };

int main(void)
{
    return apply_vip_range(first_vip, port, vip_count, backends, ARRAY_SIZE(backends));
}
