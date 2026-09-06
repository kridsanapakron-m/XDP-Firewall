#include <arpa/inet.h>
#include <errno.h>
#include <linux/in.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xdp_lb_common.h"

#define MAP_DIR "/sys/fs/bpf/xdp_lb_test/maps"
#define VIP_MAP_PATH MAP_DIR "/vip_map"
#define BACKEND_MAP_PATH MAP_DIR "/backend_map"
#define DEVICE_IP_MAP_PATH MAP_DIR "/device_ip_map"
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

/* -------------------------- Static configuration -------------------- */

struct backend_config {
    const char *ip;
};

struct service_config {
    const char *vip;
    __u16 port;
    const char *protocol;
    const struct backend_config *backends;
    size_t backend_count;
};

static const char *device_ip = "192.168.10.1";

static const struct backend_config server_group1[] = {
    { "192.168.10.11" },
    { "192.168.10.12" },
};

static const struct backend_config server_group2[] = {
    { "192.168.20.11" },
    { "192.168.20.12" },
    { "192.168.20.13" },
};

static const struct service_config services[] = {
    {
        .vip = "10.0.0.100",
        .port = 80,
        .protocol = "tcp",
        .backends = server_group1,
        .backend_count = ARRAY_SIZE(server_group1),
    },
    {
        .vip = "10.0.0.101",
        .port = 443,
        .protocol = "tcp",
        .backends = server_group2,
        .backend_count = ARRAY_SIZE(server_group2),
    },
};

/* ---------------------------- Input parsing -------------------------- */

static int parse_number(const char *text, __u32 minimum, __u32 maximum,
                        __u32 *value, const char *name)
{
    char *invalid;
    unsigned long number;

    errno = 0;
    number = strtoul(text, &invalid, 10);
    if (errno || invalid == text || *invalid ||
        number < minimum || number > maximum) {
        fprintf(stderr, "invalid %s: %s\n", name, text);
        return -1;
    }

    *value = (__u32)number;
    return 0;
}

static int parse_port(const char *text, __be16 *port)
{
    __u32 number;

    if (parse_number(text, 1, 65535, &number, "VIP port"))
        return -1;

    *port = htons((__u16)number);
    return 0;
}

static int parse_protocol(const char *text, __u8 *protocol)
{
    if (!strcmp(text, "tcp")) {
        *protocol = IPPROTO_TCP;
        return 0;
    }
    if (!strcmp(text, "udp")) {
        *protocol = IPPROTO_UDP;
        return 0;
    }
    fprintf(stderr, "invalid protocol: %s\n", text);
    return -1;
}

static int parse_ipv4(const char *text, __be32 *address, const char *name)
{
    if (inet_pton(AF_INET, text, address) == 1)
        return 0;

    fprintf(stderr, "invalid %s address: %s\n", name, text);
    return -1;
}

static int parse_toggle(const char *text, __u32 *value, const char *name)
{
    if (!strcmp(text, "on")) {
        *value = 1;
        return 0;
    }
    if (!strcmp(text, "off")) {
        *value = 0;
        return 0;
    }
    fprintf(stderr, "invalid %s: %s (expected on/off)\n", name, text);
    return -1;
}

static int parse_vip(char **arguments, struct vip_key *vip)
{
    memset(vip, 0, sizeof(*vip));

    if (parse_ipv4(arguments[0], &vip->address, "VIP") ||
        parse_port(arguments[1], &vip->port) ||
        parse_protocol(arguments[2], &vip->protocol))
        return -1;

    return 0;
}

static void build_backend_key(struct backend_key *backend_key,
                              const struct vip_key *vip, __u32 slot)
{
    memset(backend_key, 0, sizeof(*backend_key));
    backend_key->vip = *vip;
    backend_key->slot = slot;
}

static int parse_backend_key(char **arguments, struct backend_key *key)
{
    struct vip_key vip;
    __u32 slot;

    if (parse_vip(arguments, &vip) ||
        parse_number(arguments[3], 0, MAX_BACKENDS_PER_VIP - 1,
                     &slot, "backend slot"))
        return -1;

    build_backend_key(key, &vip, slot);
    return 0;
}

/* ------------------------------- Map I/O ----------------------------- */

static int open_map(const char *path)
{
    int fd = bpf_obj_get(path);

    if (fd < 0)
        fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
    return fd;
}

static int change_map(const char *path, const void *key, const void *value)
{
    int fd = open_map(path);
    int result;

    if (fd < 0)
        return -1;

    result = value ? bpf_map_update_elem(fd, key, value, BPF_ANY)
                   : bpf_map_delete_elem(fd, key);
    close(fd);

    if (!value && result == -ENOENT)
        return 0;
    if (result) {
        fprintf(stderr, "cannot %s %s: %s\n",
                value ? "update" : "delete from", path, strerror(-result));
        return -1;
    }
    return 0;
}

/* ------------------------------ Commands ----------------------------- */

static int add_vip(char **arguments)
{
    struct vip_value value = {};
    struct vip_key vip;

    if (parse_vip(arguments, &vip))
        return -1;
    if (parse_number(arguments[3], 1, MAX_BACKENDS_PER_VIP,
                     &value.backend_count, "backend count"))
        return -1;

    /*
     * BPF_ANY makes add-vip an upsert, so it also changes backend_count.
     * Scale up:   create the new backend slot, then increase the count.
     * Scale down: decrease the count, then delete the unused backend slot.
     */
    return change_map(VIP_MAP_PATH, &vip, &value);
}

static int delete_vip(char **arguments)
{
    struct vip_key vip;

    if (parse_vip(arguments, &vip))
        return -1;
    return change_map(VIP_MAP_PATH, &vip, NULL);
}

static int set_backend(char **arguments)
{
    struct backend backend = {};
    struct backend_key backend_key;

    if (parse_backend_key(arguments, &backend_key) ||
        parse_ipv4(arguments[4], &backend.address, "backend"))
        return -1;

    /* A backend may be prepared before its VIP is activated. */
    return change_map(BACKEND_MAP_PATH, &backend_key, &backend);
}

static int delete_backend(char **arguments)
{
    struct backend_key backend_key;

    if (parse_backend_key(arguments, &backend_key))
        return -1;
    return change_map(BACKEND_MAP_PATH, &backend_key, NULL);
}

/* Also resets fragment_handling_enabled to off; re-enable it afterward. */
static int set_device_ip(char **arguments)
{
    struct device_config device = {};
    __u32 key = 0;

    if (parse_ipv4(arguments[0], &device.ip_address, "device IP"))
        return -1;
    return change_map(DEVICE_IP_MAP_PATH, &key, &device);
}

static int set_fragment_handling(char **arguments)
{
    struct device_config device = {};
    __u32 key = 0;
    __u32 enabled;
    int fd;
    int result;

    if (parse_toggle(arguments[0], &enabled, "fragment handling"))
        return -1;

    fd = open_map(DEVICE_IP_MAP_PATH);
    if (fd < 0)
        return -1;

    if (bpf_map_lookup_elem(fd, &key, &device)) {
        fprintf(stderr, "device IP is not configured yet; run set-device-ip first\n");
        close(fd);
        return -1;
    }

    device.fragment_handling_enabled = enabled;
    result = bpf_map_update_elem(fd, &key, &device, BPF_ANY);
    close(fd);

    if (result) {
        fprintf(stderr, "cannot update %s: %s\n", DEVICE_IP_MAP_PATH, strerror(-result));
        return -1;
    }
    return 0;
}

static int apply_config(char **arguments)
{
    /* Zero-init leaves fragment_handling_enabled off; enable it explicitly. */
    struct device_config device = {};
    __u32 device_key = 0;

    (void)arguments;

    if (parse_ipv4(device_ip, &device.ip_address, "device IP") ||
        change_map(DEVICE_IP_MAP_PATH, &device_key, &device))
        return -1;

    for (size_t service_index = 0;
         service_index < ARRAY_SIZE(services); service_index++) {
        const struct service_config *service = &services[service_index];
        struct vip_value vip_value = {};
        struct vip_key vip;

        memset(&vip, 0, sizeof(vip));
        if (parse_ipv4(service->vip, &vip.address, "VIP") ||
            parse_protocol(service->protocol, &vip.protocol))
            return -1;
        if (!service->port) {
            fprintf(stderr, "invalid VIP port: %u\n", service->port);
            return -1;
        }
        if (!service->backend_count ||
            service->backend_count > MAX_BACKENDS_PER_VIP) {
            fprintf(stderr, "invalid backend count: %zu\n",
                    service->backend_count);
            return -1;
        }

        vip.port = htons(service->port);
        vip_value.backend_count = (__u32)service->backend_count;

        for (size_t slot = 0; slot < service->backend_count; slot++) {
            const struct backend_config *configured_backend =
                &service->backends[slot];
            struct backend backend = {};
            struct backend_key backend_key;

            if (parse_ipv4(configured_backend->ip, &backend.address,
                           "backend"))
                return -1;

            build_backend_key(&backend_key, &vip, (__u32)slot);
            if (change_map(BACKEND_MAP_PATH, &backend_key, &backend))
                return -1;
        }

        if (change_map(VIP_MAP_PATH, &vip, &vip_value))
            return -1;
    }

    return 0;
}

/* -------------------------- Command dispatch ------------------------- */

struct command {
    const char *name;
    const char *parameters;
    size_t argument_count;
    int (*run)(char **arguments);
};

static const struct command commands[] = {
    { "apply-config", "", 0, apply_config },
    { "add-vip", "<vip_ip> <port> <tcp|udp> <backend_count>", 4, add_vip },
    { "del-vip", "<vip_ip> <port> <tcp|udp>", 3, delete_vip },
    { "set-backend", "<vip_ip> <port> <tcp|udp> <slot> <backend_ip>", 5, set_backend },
    { "del-backend", "<vip_ip> <port> <tcp|udp> <slot>", 4, delete_backend },
    { "set-device-ip", "<device_ip>", 1, set_device_ip },
    { "set-fragment-handling", "<on|off>", 1, set_fragment_handling },
};

static void usage(const char *program)
{
    fprintf(stderr, "Usage:\n");
    for (size_t i = 0; i < ARRAY_SIZE(commands); i++)
        fprintf(stderr, "  %s %s%s%s\n", program, commands[i].name,
                commands[i].parameters[0] ? " " : "", commands[i].parameters);
}

static const struct command *find_command(const char *name)
{
    for (size_t i = 0; i < ARRAY_SIZE(commands); i++) {
        if (!strcmp(name, commands[i].name))
            return &commands[i];
    }
    return NULL;
}

int main(int argc, char **argv)
{
    const struct command *command;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    command = find_command(argv[1]);
    if (!command || (size_t)(argc - 2) != command->argument_count) {
        usage(argv[0]);
        return 1;
    }
    return command->run(argv + 2) ? 1 : 0;
}

/*
 * Apply the static configuration:
 *   sudo ./xdp_lb_ctl apply-config
 *
 * Example configuration
 * ---------------------
 *   VIP:              10.0.0.100:80/TCP
 *   Load balancer IP: 192.168.10.1
 *   Backend 0:        192.168.10.11
 *   Backend 1:        192.168.10.12
 *
 * Configure the tunnel source IP:
 *   sudo ./xdp_lb_ctl set-device-ip 192.168.10.1
 *
 * Prepare every backend slot before activating the VIP:
 *   sudo ./xdp_lb_ctl set-backend 10.0.0.100 80 tcp 0 192.168.10.11
 *   sudo ./xdp_lb_ctl set-backend 10.0.0.100 80 tcp 1 192.168.10.12
 *   sudo ./xdp_lb_ctl add-vip 10.0.0.100 80 tcp 2
 *
 * add-vip is an upsert. Scale up by preparing the new slot first:
 *   sudo ./xdp_lb_ctl set-backend 10.0.0.100 80 tcp 2 192.168.10.13
 *   sudo ./xdp_lb_ctl add-vip 10.0.0.100 80 tcp 3
 *
 * Scale down by decreasing backend_count before deleting the slot:
 *   sudo ./xdp_lb_ctl add-vip 10.0.0.100 80 tcp 2
 *   sudo ./xdp_lb_ctl del-backend 10.0.0.100 80 tcp 2
 *
 * Delete a service: remove the VIP first, then its backend slots.
 *   sudo ./xdp_lb_ctl del-vip 10.0.0.100 80 tcp
 *   sudo ./xdp_lb_ctl del-backend 10.0.0.100 80 tcp 0
 *   sudo ./xdp_lb_ctl del-backend 10.0.0.100 80 tcp 1
 *
 * Changing backend_count can move existing flows to different backends
 * because the current selection is: flow_hash modulo backend_count.
 */
