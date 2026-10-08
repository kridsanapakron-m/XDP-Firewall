#include <arpa/inet.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>

#include "xdp_lb_common.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

struct service {
    const char *vip;
    __u16 port;
    const char *protocol;
    const char *backends[MAX_BACKENDS_PER_VIP];
};

static const char *map_dir = "/sys/fs/bpf/xdp_lb_test/maps";
static const char *device_ip = "192.168.100.20";
static const int fragment_handling = 0;
static const int icmp_pmtu = 0;
static const int flush_first = 1;

static const struct service services[] = {
    {
        .vip = "192.168.50.100",
        .port = 8080,
        .protocol = "tcp",
        .backends = { "192.168.201.2", "192.168.202.2", "192.168.203.2" },
    },
    {
        .vip = "192.168.50.100",
        .port = 8080,
        .protocol = "udp",
        .backends = { "192.168.201.2", "192.168.202.2", "192.168.203.2" },
    },
};

static int open_map(const char *name)
{
    char path[256];
    int fd;

    snprintf(path, sizeof(path), "%s/%s", map_dir, name);
    fd = bpf_obj_get(path);
    if (fd < 0)
        fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
    return fd;
}

static int flush_map(int fd)
{
    union {
        struct vip_key vip;
        struct backend_key backend;
    } key;

    while (!bpf_map_get_next_key(fd, NULL, &key)) {
        if (bpf_map_delete_elem(fd, &key))
            return -1;
    }
    return 0;
}

static int apply_service(int vip_fd, int backend_fd, const struct service *service)
{
    struct backend_key key = {
        .vip = {
            .address = inet_addr(service->vip),
            .port = htons(service->port),
            .protocol = strcmp(service->protocol, "udp") ? IPPROTO_TCP : IPPROTO_UDP,
        },
    };
    struct vip_value value = {};

    for (key.slot = 0; key.slot < MAX_BACKENDS_PER_VIP && service->backends[key.slot];
         key.slot++) {
        struct backend backend = { .address = inet_addr(service->backends[key.slot]) };

        if (bpf_map_update_elem(backend_fd, &key, &backend, BPF_ANY))
            return -1;
    }
    value.backend_count = key.slot;
    if (bpf_map_update_elem(vip_fd, &key.vip, &value, BPF_ANY))
        return -1;

    printf("%s:%u/%s ->", service->vip, service->port, service->protocol);
    for (__u32 slot = 0; slot < value.backend_count; slot++)
        printf(" %s", service->backends[slot]);
    printf("\n");
    return 0;
}

int main(void)
{
    struct device_config device = {
        .ip_address = inet_addr(device_ip),
        .fragment_handling_enabled = fragment_handling,
        .icmp_pmtu_enabled = icmp_pmtu,
    };
    int vip_fd = open_map("vip_map");
    int backend_fd = open_map("backend_map");
    int device_fd = open_map("device_ip_map");

    if (vip_fd < 0 || backend_fd < 0 || device_fd < 0)
        return 1;

    if (flush_first && (flush_map(vip_fd) || flush_map(backend_fd)))
        goto fail;
    if (bpf_map_update_elem(device_fd, &(__u32){0}, &device, BPF_ANY))
        goto fail;
    printf("device %s fragment_handling=%d icmp_pmtu=%d\n",
           device_ip, fragment_handling, icmp_pmtu);

    for (size_t index = 0; index < ARRAY_SIZE(services); index++) {
        if (apply_service(vip_fd, backend_fd, &services[index]))
            goto fail;
    }
    return 0;

fail:
    fprintf(stderr, "cannot write maps: %s\n", strerror(errno));
    return 1;
}
