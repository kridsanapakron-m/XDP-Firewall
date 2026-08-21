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

static void usage(const char *program)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s add-vip <vip_ip> <port> <tcp|udp> <backend_count>\n", program);
    fprintf(stderr, "  %s del-vip <vip_ip> <port> <tcp|udp>\n", program);
    fprintf(stderr, "  %s set-backend <vip_ip> <port> <tcp|udp> <slot> <backend_ip> <backend_mac>\n", program);
    fprintf(stderr, "  %s del-backend <vip_ip> <port> <tcp|udp> <slot>\n", program);
    fprintf(stderr, "  %s set-device-ip <device_ip>\n", program);
    fprintf(stderr, "  %s list\n", program);
}

/* ---------------------------- Input parsing -------------------------- */

static int parse_port(const char *text, __be16 *port)
{
    char *invalid;
    unsigned long number;

    errno = 0;
    number = strtoul(text, &invalid, 10);
    if (errno || invalid == text || *invalid || number == 0 || number > 65535)
        return -1;

    *port = htons((__u16)number);
    return 0;
}

static int parse_uint32(const char *text, __u32 *value)
{
    char *invalid;
    unsigned long number;

    errno = 0;
    number = strtoul(text, &invalid, 10);
    if (errno || invalid == text || *invalid || number > 0xffffffffUL)
        return -1;

    *value = (__u32)number;
    return 0;
}

static int parse_backend_number(const char *text, __u32 *value, __u32 minimum, __u32 maximum, const char *name)
{
    if (parse_uint32(text, value) || *value < minimum || *value > maximum) {
        fprintf(stderr, "invalid backend %s: %s\n", name, text);
        return -1;
    }

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
    return -1;
}

static int parse_vip(char **arguments, struct vip_key *vip)
{
    memset(vip, 0, sizeof(*vip));

    if (inet_pton(AF_INET, arguments[0], &vip->address) != 1) {
        fprintf(stderr, "invalid VIP address: %s\n", arguments[0]);
        return -1;
    }
    if (parse_port(arguments[1], &vip->port)) {
        fprintf(stderr, "invalid VIP port: %s\n", arguments[1]);
        return -1;
    }
    if (parse_protocol(arguments[2], &vip->protocol)) {
        fprintf(stderr, "invalid protocol: %s\n", arguments[2]);
        return -1;
    }

    return 0;
}

static int parse_mac(const char *text, __u8 mac[ETH_ALEN])
{
    unsigned int bytes[ETH_ALEN];
    int consumed = 0;

    if (sscanf(text, "%x:%x:%x:%x:%x:%x%n", &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5], &consumed) != ETH_ALEN || text[consumed] != '\0')
        return -1;

    for (int i = 0; i < ETH_ALEN; i++) {
        if (bytes[i] > 0xff)
            return -1;
        mac[i] = bytes[i];
    }
    return 0;
}

static void build_backend_key(struct backend_key *backend_key, const struct vip_key *vip, __u32 slot)
{
    memset(backend_key, 0, sizeof(*backend_key));
    backend_key->vip = *vip;
    backend_key->slot = slot;
}

/* ------------------------------- Map I/O ----------------------------- */

static int open_map(const char *path)
{
    int fd = bpf_obj_get(path);

    if (fd < 0)
        fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
    return fd;
}

static int update_map(const char *path, const void *key, const void *value)
{
    int fd = open_map(path);
    int result;

    if (fd < 0)
        return -1;
    result = bpf_map_update_elem(fd, key, value, BPF_ANY);
    if (result)
        fprintf(stderr, "cannot update %s: %s\n", path, strerror(errno));
    close(fd);
    return result;
}

static int delete_map_entry(const char *path, const void *key)
{
    int fd = open_map(path);
    int result;

    if (fd < 0)
        return -1;
    result = bpf_map_delete_elem(fd, key);
    if (result && errno == ENOENT)
        result = 0;
    else if (result)
        fprintf(stderr, "cannot delete from %s: %s\n", path, strerror(errno));
    close(fd);
    return result;
}

/* ------------------------------ Commands ----------------------------- */

static int add_vip(int count, char **arguments)
{
    struct vip_value value = {};
    struct vip_key vip;

    if (count != 4 || parse_vip(arguments, &vip))
        return -1;
    if (parse_backend_number(arguments[3], &value.backend_count, 1, MAX_BACKENDS_PER_VIP, "count"))
        return -1;

    /*
     * BPF_ANY makes add-vip an upsert, so it also changes backend_count.
     * Scale up:   create the new backend slot, then increase the count.
     * Scale down: decrease the count, then delete the unused backend slot.
     */
    return update_map(VIP_MAP_PATH, &vip, &value);
}

static int delete_vip(int count, char **arguments)
{
    struct vip_key vip;

    if (count != 3 || parse_vip(arguments, &vip))
        return -1;
    return delete_map_entry(VIP_MAP_PATH, &vip);
}

static int set_backend(int count, char **arguments)
{
    struct backend backend = {};
    struct backend_key backend_key = {};
    struct vip_key vip;
    __u32 slot;

    if (count != 6 || parse_vip(arguments, &vip))
        return -1;
    if (parse_backend_number(arguments[3], &slot, 0, MAX_BACKENDS_PER_VIP - 1, "slot"))
        return -1;
    if (inet_pton(AF_INET, arguments[4], &backend.address) != 1) {
        fprintf(stderr, "invalid backend address: %s\n", arguments[4]);
        return -1;
    }
    if (parse_mac(arguments[5], backend.mac)) {
        fprintf(stderr, "invalid backend MAC: %s\n", arguments[5]);
        return -1;
    }

    /* A backend may be prepared before its VIP is activated. */
    build_backend_key(&backend_key, &vip, slot);
    return update_map(BACKEND_MAP_PATH, &backend_key, &backend);
}

static int delete_backend(int count, char **arguments)
{
    struct backend_key backend_key = {};
    struct vip_key vip;
    __u32 slot;

    if (count != 4 || parse_vip(arguments, &vip))
        return -1;
    if (parse_backend_number(arguments[3], &slot, 0, MAX_BACKENDS_PER_VIP - 1, "slot"))
        return -1;

    build_backend_key(&backend_key, &vip, slot);
    return delete_map_entry(BACKEND_MAP_PATH, &backend_key);
}

static int set_device_ip(int count, char **arguments)
{
    struct device_config device = {};
    __u32 key = 0;

    if (count != 1)
        return -1;
    if (inet_pton(AF_INET, arguments[0], &device.ip_address) != 1) {
        fprintf(stderr, "invalid device IP address: %s\n", arguments[0]);
        return -1;
    }
    return update_map(DEVICE_IP_MAP_PATH, &key, &device);
}

static const char *protocol_name(__u8 protocol)
{
    if (protocol == IPPROTO_TCP)
        return "tcp";
    if (protocol == IPPROTO_UDP)
        return "udp";
    return "unknown";
}

static void print_vip_name(const struct vip_key *vip)
{
    char address[INET_ADDRSTRLEN] = "invalid";

    inet_ntop(AF_INET, &vip->address, address, sizeof(address));
    printf("%s:%u/%s", address, ntohs(vip->port), protocol_name(vip->protocol));
}

static void print_backend(const struct backend *backend)
{
    char address[INET_ADDRSTRLEN] = "invalid";

    inet_ntop(AF_INET, &backend->address, address, sizeof(address));
    printf("%s %02x:%02x:%02x:%02x:%02x:%02x", address, backend->mac[0], backend->mac[1], backend->mac[2], backend->mac[3], backend->mac[4], backend->mac[5]);
}

/* Print every active VIP and the backend slots that it expects. */
static int list_vips(int vip_fd, int backend_fd)
{
    struct vip_key current;
    struct vip_key next;
    const void *previous = NULL;

    for (;;) {
        struct vip_value vip_value;

        if (bpf_map_get_next_key(vip_fd, previous, &next)) {
            if (errno == ENOENT)
                return 0;
            fprintf(stderr, "cannot iterate vip_map: %s\n", strerror(errno));
            return -1;
        }

        current = next;
        previous = &current;

        if (bpf_map_lookup_elem(vip_fd, &current, &vip_value)) {
            /* The entry may have been deleted while list was running. */
            if (errno == ENOENT)
                continue;
            fprintf(stderr, "cannot read vip_map: %s\n", strerror(errno));
            return -1;
        }

        print_vip_name(&current);
        printf(" backends=%u\n", vip_value.backend_count);

        if (vip_value.backend_count == 0 || vip_value.backend_count > MAX_BACKENDS_PER_VIP) {
            printf("  INVALID_COUNT\n");
            continue;
        }

        for (__u32 slot = 0; slot < vip_value.backend_count; slot++) {
            struct backend_key backend_key = {};
            struct backend backend;

            build_backend_key(&backend_key, &current, slot);
            printf("  slot %u -> ", slot);

            if (bpf_map_lookup_elem(backend_fd, &backend_key, &backend)) {
                if (errno == ENOENT) {
                    printf("MISSING\n");
                    continue;
                }
                fprintf(stderr, "cannot read backend_map: %s\n", strerror(errno));
                return -1;
            }

            print_backend(&backend);
            printf("\n");
        }
    }
}

/* Find backend entries that cannot be selected by the current vip_map. */
static int list_unusable_backends(int vip_fd, int backend_fd)
{
    struct backend_key current;
    struct backend_key next;
    const void *previous = NULL;
    int printed_heading = 0;

    for (;;) {
        struct vip_value vip_value;
        const char *problem = NULL;

        if (bpf_map_get_next_key(backend_fd, previous, &next)) {
            if (errno == ENOENT)
                return 0;
            fprintf(stderr, "cannot iterate backend_map: %s\n", strerror(errno));
            return -1;
        }

        current = next;
        previous = &current;

        if (bpf_map_lookup_elem(vip_fd, &current.vip, &vip_value)) {
            if (errno == ENOENT)
                problem = "ORPHAN";
            else {
                fprintf(stderr, "cannot read vip_map: %s\n", strerror(errno));
                return -1;
            }
        } else if (vip_value.backend_count == 0 || vip_value.backend_count > MAX_BACKENDS_PER_VIP) {
            problem = "INVALID_VIP";
        } else if (current.slot >= vip_value.backend_count) {
            problem = "OUT_OF_RANGE";
        }

        if (!problem)
            continue;

        if (!printed_heading) {
            printf("Backend configuration problems:\n");
            printed_heading = 1;
        }

        printf("  ");
        print_vip_name(&current.vip);
        printf(" slot %u -> %s\n", current.slot, problem);
    }
}

static int list_services(int count)
{
    int vip_fd;
    int backend_fd;
    int result;

    if (count != 0)
        return -1;

    vip_fd = open_map(VIP_MAP_PATH);
    backend_fd = open_map(BACKEND_MAP_PATH);
    if (vip_fd < 0 || backend_fd < 0) {
        if (vip_fd >= 0)
            close(vip_fd);
        if (backend_fd >= 0)
            close(backend_fd);
        return -1;
    }

    result = list_vips(vip_fd, backend_fd);
    if (!result)
        result = list_unusable_backends(vip_fd, backend_fd);

    close(backend_fd);
    close(vip_fd);
    return result;
}

int main(int argc, char **argv)
{
    const char *command;
    char **arguments;
    int count;
    int result = -1;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    command = argv[1];
    arguments = &argv[2];
    count = argc - 2;

    if (!strcmp(command, "add-vip"))
        result = add_vip(count, arguments);
    else if (!strcmp(command, "del-vip"))
        result = delete_vip(count, arguments);
    else if (!strcmp(command, "set-backend"))
        result = set_backend(count, arguments);
    else if (!strcmp(command, "del-backend"))
        result = delete_backend(count, arguments);
    else if (!strcmp(command, "set-device-ip"))
        result = set_device_ip(count, arguments);
    else if (!strcmp(command, "list"))
        result = list_services(count);

    if (result) {
        usage(argv[0]);
        return 1;
    }
    return 0;
}

/*
 * Example configuration
 * ---------------------
 *
 * Example addresses:
 *   VIP:              10.0.0.100:80/TCP
 *   Load balancer IP: 192.168.10.1
 *   Backend 0:        192.168.10.11  02:00:00:00:00:11
 *   Backend 1:        192.168.10.12  02:00:00:00:00:12
 *
 * 1. Set the source IP used by the outer tunnel packet:
 *
 *   sudo ./xdp_lb_ctl_test set-device-ip 192.168.10.1
 *
 * 2. Add all backend slots before activating the VIP:
 *
 *   sudo ./xdp_lb_ctl_test set-backend 10.0.0.100 80 tcp 0 192.168.10.11 02:00:00:00:00:11
 *
 *   sudo ./xdp_lb_ctl_test set-backend 10.0.0.100 80 tcp 1 192.168.10.12 02:00:00:00:00:12
 *
 * 3. Add the VIP and specify that it has two backends:
 *
 *   sudo ./xdp_lb_ctl_test add-vip 10.0.0.100 80 tcp 2
 *
 * 4. Show the configured VIPs, backends, and configuration problems:
 *
 *   sudo ./xdp_lb_ctl_test list
 *
 * Scale up from two to three backends:
 *   - Add slot 2 first.
 *   - Then update the VIP backend count to 3.
 *
 *   sudo ./xdp_lb_ctl_test set-backend 10.0.0.100 80 tcp 2 192.168.10.13 02:00:00:00:00:13
 *   sudo ./xdp_lb_ctl_test add-vip 10.0.0.100 80 tcp 3
 *
 * Scale down from three to two backends:
 *   - Reduce the VIP backend count first.
 *   - Then delete the unused slot.
 *
 *   sudo ./xdp_lb_ctl_test add-vip 10.0.0.100 80 tcp 2
 *   sudo ./xdp_lb_ctl_test del-backend 10.0.0.100 80 tcp 2
 *
 * Delete the service:
 *   - Delete the VIP first so no new packet can select its backends.
 *   - Then delete every backend slot.
 *
 *   sudo ./xdp_lb_ctl_test del-vip 10.0.0.100 80 tcp
 *   sudo ./xdp_lb_ctl_test del-backend 10.0.0.100 80 tcp 0
 *   sudo ./xdp_lb_ctl_test del-backend 10.0.0.100 80 tcp 1
 *
 * Changing backend_count can move existing flows to different backends
 * because the current selection is: flow_hash modulo backend_count.
 */
