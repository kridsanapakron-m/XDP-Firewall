/*
 * Declarative configuration loader for the XDP load balancer.
 *
 * Unlike xdp_lb_ctl, this program takes no subcommands: edit the CONFIGURATION
 * block below, rebuild, and run it once. It writes the same pinned maps with
 * the same ABI (xdp_lb_common.h), so both programs stay interchangeable.
 *
 *   make xdp_lb_conf
 *   sudo ./xdp_lb_conf            apply the configuration below
 *        ./xdp_lb_conf --dry-run  validate and print it without touching maps
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/in.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xdp_lb_common.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

/* Writes both the backend list and its length into a struct service. */
#define BACKENDS(...)                                                        \
    (const char *const[]){ __VA_ARGS__ },                                    \
    sizeof((const char *const[]){ __VA_ARGS__ }) / sizeof(const char *)

struct service {
    const char *vip;
    __u16 port;
    const char *protocol; /* "tcp" or "udp" */
    const char *const *backends;
    size_t backend_count;
};

/* ------------------------------------------------------------------------
 * CONFIGURATION -- this is the only part meant to be edited.
 * ------------------------------------------------------------------------ */

/*
 * Where the maps were pinned (bpftool prog load ... pinmaps <dir>).
 * xdp_lb_ctl has this same path compiled in as a #define, so changing it
 * here means xdp_lb_ctl can no longer find the maps.
 */
static const char *map_dir = "/sys/fs/bpf/xdp_lb_test/maps";

/* Tunnel source IP: this machine's address on the backend-facing interface. */
static const char *device_ip = "192.168.100.20";

/* Feature toggles: 1 = on, 0 = off. */
static const int fragment_handling = 0;
static const int icmp_pmtu = 0;

/*
 * Remove every VIP and backend slot already in the maps before applying, so
 * the maps end up holding exactly the services listed here. Set to 0 to add
 * to whatever is already configured instead.
 */
static const int flush_first = 1;

/*
 * One line per service. Slot numbers are assigned in list order, starting
 * at 0, and backend_count is the length of the BACKENDS() list.
 * At least one service is required; C forbids an empty initializer.
 */
static const struct service services[] = {
    {
        .vip = "192.168.50.100",
        .port = 8080,
        .protocol = "tcp",
        BACKENDS("192.168.201.2",
                 "192.168.202.2",
                 "192.168.203.2"),
    },
    /*
     * vip_map is keyed by protocol, so UDP needs its own entry even on the
     * same address and port. The fragmentation tests send UDP datagrams,
     * which would otherwise miss the lookup and be passed through untouched.
     */
    {
        .vip = "192.168.50.100",
        .port = 8080,
        .protocol = "udp",
        BACKENDS("192.168.201.2",
                 "192.168.202.2",
                 "192.168.203.2"),
    },
};

/* ------------------------------------------------------------------------
 * END OF CONFIGURATION
 * ------------------------------------------------------------------------ */

static char vip_map_path[256];
static char backend_map_path[256];
static char device_map_path[256];

static void build_map_paths(void)
{
    snprintf(vip_map_path, sizeof(vip_map_path), "%s/vip_map", map_dir);
    snprintf(backend_map_path, sizeof(backend_map_path), "%s/backend_map", map_dir);
    snprintf(device_map_path, sizeof(device_map_path), "%s/device_ip_map", map_dir);
}

static const char *format_ipv4(__be32 address)
{
    static char text[INET_ADDRSTRLEN];

    if (!inet_ntop(AF_INET, &address, text, sizeof(text)))
        return "?";
    return text;
}

static int parse_ipv4(const char *text, __be32 *address, const char *name)
{
    if (text && inet_pton(AF_INET, text, address) == 1)
        return 0;

    fprintf(stderr, "invalid %s address: %s\n", name, text ? text : "(null)");
    return -1;
}

static int parse_protocol(const char *text, __u8 *protocol)
{
    if (text && !strcmp(text, "tcp")) {
        *protocol = IPPROTO_TCP;
        return 0;
    }
    if (text && !strcmp(text, "udp")) {
        *protocol = IPPROTO_UDP;
        return 0;
    }
    fprintf(stderr, "invalid protocol: %s (expected tcp/udp)\n",
            text ? text : "(null)");
    return -1;
}

/* Turns one configuration entry into the exact key/value the maps store. */
static int build_vip(const struct service *service, size_t index,
                     struct vip_key *vip, struct vip_value *value)
{
    memset(vip, 0, sizeof(*vip));
    memset(value, 0, sizeof(*value));

    if (parse_ipv4(service->vip, &vip->address, "VIP") ||
        parse_protocol(service->protocol, &vip->protocol)) {
        fprintf(stderr, "  in services[%zu]\n", index);
        return -1;
    }
    if (!service->port) {
        fprintf(stderr, "invalid VIP port in services[%zu]: %u\n",
                index, service->port);
        return -1;
    }
    if (!service->backend_count ||
        service->backend_count > MAX_BACKENDS_PER_VIP) {
        fprintf(stderr, "invalid backend count in services[%zu]: %zu "
                "(expected 1..%d)\n",
                index, service->backend_count, MAX_BACKENDS_PER_VIP);
        return -1;
    }

    vip->port = htons(service->port);
    value->backend_count = (__u32)service->backend_count;
    return 0;
}

/* Parses every service and backend address so a typo fails before any write. */
static int validate_config(void)
{
    struct vip_key vips[ARRAY_SIZE(services)];

    for (size_t index = 0; index < ARRAY_SIZE(services); index++) {
        const struct service *service = &services[index];
        struct vip_value value;

        if (build_vip(service, index, &vips[index], &value))
            return -1;

        for (size_t slot = 0; slot < service->backend_count; slot++) {
            __be32 address;

            if (parse_ipv4(service->backends[slot], &address, "backend")) {
                fprintf(stderr, "  in services[%zu] slot %zu\n", index, slot);
                return -1;
            }
        }

        for (size_t earlier = 0; earlier < index; earlier++) {
            if (!memcmp(&vips[earlier], &vips[index], sizeof(vips[0]))) {
                fprintf(stderr, "duplicate VIP in services[%zu] and "
                        "services[%zu]: %s:%u/%s\n",
                        earlier, index, service->vip, service->port,
                        service->protocol);
                return -1;
            }
        }
    }

    if (fragment_handling != 0 && fragment_handling != 1) {
        fprintf(stderr, "fragment_handling must be 0 or 1\n");
        return -1;
    }
    if (icmp_pmtu != 0 && icmp_pmtu != 1) {
        fprintf(stderr, "icmp_pmtu must be 0 or 1\n");
        return -1;
    }
    return 0;
}

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

/*
 * Deletes every entry by repeatedly taking the map's first key, which always
 * makes progress because that key is the one removed.
 */
static int flush_map(const char *path, const char *name)
{
    union {
        struct vip_key vip;
        struct backend_key backend;
    } key;
    unsigned int removed = 0;
    int fd = open_map(path);
    int result = 0;

    if (fd < 0)
        return -1;

    while (!bpf_map_get_next_key(fd, NULL, &key)) {
        result = bpf_map_delete_elem(fd, &key);
        if (result && result != -ENOENT) {
            fprintf(stderr, "cannot delete from %s: %s\n",
                    path, strerror(-result));
            close(fd);
            return -1;
        }
        removed++;
    }

    close(fd);
    printf("  flushed %s: %u entr%s removed\n",
           name, removed, removed == 1 ? "y" : "ies");
    return 0;
}

/* VIPs go first so no packet can reach a backend slot that is about to go. */
static int flush_maps(void)
{
    return flush_map(vip_map_path, "vip_map") ||
           flush_map(backend_map_path, "backend_map") ? -1 : 0;
}

/* One write carries the device IP and both toggles, so none can reset another. */
static int apply_device_config(void)
{
    struct device_config device = {};
    __u32 key = 0;

    if (parse_ipv4(device_ip, &device.ip_address, "device IP"))
        return -1;

    device.fragment_handling_enabled = (__u32)fragment_handling;
    device.icmp_pmtu_enabled = (__u32)icmp_pmtu;

    if (change_map(device_map_path, &key, &device))
        return -1;

    printf("  device IP %s, fragment handling %s, PMTU ICMP %s\n",
           device_ip, fragment_handling ? "on" : "off",
           icmp_pmtu ? "on" : "off");
    return 0;
}

/* Every backend slot exists before the VIP is activated, as xdp_lb_ctl does. */
static int apply_service(const struct service *service, size_t index)
{
    struct vip_value vip_value;
    struct vip_key vip;

    if (build_vip(service, index, &vip, &vip_value))
        return -1;

    for (size_t slot = 0; slot < service->backend_count; slot++) {
        struct backend backend = {};
        struct backend_key backend_key;

        if (parse_ipv4(service->backends[slot], &backend.address, "backend"))
            return -1;

        memset(&backend_key, 0, sizeof(backend_key));
        backend_key.vip = vip;
        backend_key.slot = (__u32)slot;

        if (change_map(backend_map_path, &backend_key, &backend))
            return -1;
    }

    if (change_map(vip_map_path, &vip, &vip_value))
        return -1;

    printf("  %s:%u/%s -> %u backend%s\n", service->vip, service->port,
           service->protocol, vip_value.backend_count,
           vip_value.backend_count == 1 ? "" : "s");
    for (size_t slot = 0; slot < service->backend_count; slot++)
        printf("      slot %zu: %s\n", slot, service->backends[slot]);

    return 0;
}

/* Reads the maps back so the printed result is map state, not intent. */
static int verify_service(const struct service *service, size_t index)
{
    struct vip_value vip_value = {};
    struct vip_key vip;
    struct vip_value expected;
    int vip_fd;
    int backend_fd;
    int failures = 0;

    if (build_vip(service, index, &vip, &expected))
        return -1;

    vip_fd = open_map(vip_map_path);
    if (vip_fd < 0)
        return -1;
    backend_fd = open_map(backend_map_path);
    if (backend_fd < 0) {
        close(vip_fd);
        return -1;
    }

    if (bpf_map_lookup_elem(vip_fd, &vip, &vip_value)) {
        fprintf(stderr, "  %s:%u/%s is missing from vip_map\n",
                service->vip, service->port, service->protocol);
        failures++;
    } else if (vip_value.backend_count != expected.backend_count) {
        fprintf(stderr, "  %s:%u/%s backend_count is %u, expected %u\n",
                service->vip, service->port, service->protocol,
                vip_value.backend_count, expected.backend_count);
        failures++;
    } else {
        printf("  %s:%u/%s backend_count %u\n", service->vip, service->port,
               service->protocol, vip_value.backend_count);
    }

    for (size_t slot = 0; slot < service->backend_count; slot++) {
        struct backend backend = {};
        struct backend_key backend_key;

        memset(&backend_key, 0, sizeof(backend_key));
        backend_key.vip = vip;
        backend_key.slot = (__u32)slot;

        if (bpf_map_lookup_elem(backend_fd, &backend_key, &backend)) {
            fprintf(stderr, "      slot %zu is missing from backend_map\n", slot);
            failures++;
            continue;
        }
        printf("      slot %zu: %s\n", slot, format_ipv4(backend.address));
    }

    close(backend_fd);
    close(vip_fd);
    return failures ? -1 : 0;
}

static int verify_device_config(void)
{
    struct device_config device = {};
    __u32 key = 0;
    int fd = open_map(device_map_path);

    if (fd < 0)
        return -1;

    if (bpf_map_lookup_elem(fd, &key, &device)) {
        fprintf(stderr, "  device_ip_map has no entry\n");
        close(fd);
        return -1;
    }
    close(fd);

    printf("  device IP %s, fragment handling %s, PMTU ICMP %s\n",
           format_ipv4(device.ip_address),
           device.fragment_handling_enabled ? "on" : "off",
           device.icmp_pmtu_enabled ? "on" : "off");
    return 0;
}

static void print_config(void)
{
    printf("configuration (%zu service%s)\n", ARRAY_SIZE(services),
           ARRAY_SIZE(services) == 1 ? "" : "s");
    printf("  maps:      %s\n", map_dir);
    printf("  device IP: %s\n", device_ip);
    printf("  fragment handling %s, PMTU ICMP %s, flush first %s\n",
           fragment_handling ? "on" : "off", icmp_pmtu ? "on" : "off",
           flush_first ? "yes" : "no");

    for (size_t index = 0; index < ARRAY_SIZE(services); index++) {
        const struct service *service = &services[index];

        printf("  %s:%u/%s\n", service->vip, service->port, service->protocol);
        for (size_t slot = 0; slot < service->backend_count; slot++)
            printf("      slot %zu: %s\n", slot, service->backends[slot]);
    }
}

int main(int argc, char **argv)
{
    int dry_run = 0;

    /* Keep progress lines in order with the error messages on stderr. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc > 2 || (argc == 2 && strcmp(argv[1], "--dry-run"))) {
        fprintf(stderr, "Usage: %s [--dry-run]\n", argv[0]);
        return 1;
    }
    dry_run = argc == 2;

    build_map_paths();

    if (validate_config())
        return 1;

    print_config();

    if (dry_run) {
        printf("\ndry run: configuration is valid, no map was changed\n");
        return 0;
    }

    printf("\napplying\n");
    if (flush_first && flush_maps())
        return 1;
    if (apply_device_config())
        return 1;
    for (size_t index = 0; index < ARRAY_SIZE(services); index++) {
        if (apply_service(&services[index], index))
            return 1;
    }

    printf("\nverifying (read back from the maps)\n");
    if (verify_device_config())
        return 1;
    for (size_t index = 0; index < ARRAY_SIZE(services); index++) {
        if (verify_service(&services[index], index))
            return 1;
    }

    printf("\nconfiguration applied\n");
    return 0;
}
