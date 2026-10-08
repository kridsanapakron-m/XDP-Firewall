#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "xdp_lb_common.h"

#define MISSED_ROUNDS_LIMIT 3

static const char usage[] =
    "usage: xdp_lb_awfd [-m max_weight] [-i interval_ms] [--static]\n"
    "  -m        largest weight m, 1..16 (default 4, Figure 10)\n"
    "  -i        polling interval in ms (default 500, Figure 12)\n"
    "  --static  weights from capacity C only (WCMP) instead of available capacity\n";

struct probed_backend {
    __be32 address;
    __u32 utilization_milli;
    __u32 capacity_milli;
    __u32 missed_rounds;
};

static const char *map_dir = "/sys/fs/bpf/xdp_lb_test/maps";
static struct probed_backend probed[MAX_BACKEND_SLOTS];
static size_t probed_count;
static __u32 max_weight = 4;
static long long interval_ms = 500;
static int static_weights;

static long long now_ms(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * 1000LL + now.tv_nsec / 1000000;
}

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

static struct probed_backend *find_probed(__be32 address, int add)
{
    for (size_t index = 0; index < probed_count; index++)
        if (probed[index].address == address)
            return &probed[index];
    if (!add || probed_count == MAX_BACKEND_SLOTS)
        return NULL;
    probed[probed_count] = (struct probed_backend){
        .address = address,
        .missed_rounds = MISSED_ROUNDS_LIMIT + 1,
    };
    return &probed[probed_count++];
}

static __u32 backend_available(const struct probed_backend *backend)
{
    if (!backend || backend->missed_rounds > MISSED_ROUNDS_LIMIT)
        return 0;
    if (static_weights)
        return backend->capacity_milli;
    if (backend->utilization_milli >= AWFD_MILLI)
        return 0;
    return (__u64)(AWFD_MILLI - backend->utilization_milli) * backend->capacity_milli / AWFD_MILLI;
}

static __u32 build_vip_classes(const __be32 *addresses, int count, struct awfd_classes *classes)
{
    __u32 available[MAX_BACKENDS_PER_VIP], max_available = 0;

    for (int slot = 0; slot < count; slot++) {
        available[slot] = backend_available(find_probed(addresses[slot], 1));
        if (available[slot] > max_available)
            max_available = available[slot];
    }

    *classes = (struct awfd_classes){};
    for (int slot = 0; slot < count; slot++) {
        __u32 weight = max_available ? (__u64)max_weight * available[slot] / max_available : 0;

        if (weight)
            classes->members[weight - 1][classes->class_size[weight - 1]++] = slot;
    }
    for (__u32 class = 0; class < AWFD_MAX_WEIGHT; class++) {
        classes->weight_sum += (class + 1) * classes->class_size[class];
        classes->range_end[class] = classes->weight_sum;
    }
    return max_available;
}

static void probe_backends(int sock, __u32 sequence, long long deadline)
{
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(AWFD_AGENT_PORT) };
    __be32 wire_sequence = htonl(sequence);
    size_t pending = probed_count;

    for (size_t index = 0; index < probed_count; index++) {
        if (probed[index].missed_rounds <= MISSED_ROUNDS_LIMIT)
            probed[index].missed_rounds++;
        to.sin_addr.s_addr = probed[index].address;
        sendto(sock, &wire_sequence, sizeof(wire_sequence), 0, (void *)&to, sizeof(to));
    }

    while (pending) {
        struct pollfd ready = { .fd = sock, .events = POLLIN };
        long long remaining_ms = deadline - now_ms();
        struct sockaddr_in from;
        socklen_t from_length = sizeof(from);
        struct awfd_probe_reply reply;
        struct probed_backend *backend;

        if (remaining_ms <= 0 || poll(&ready, 1, remaining_ms) <= 0)
            break;
        if (recvfrom(sock, &reply, sizeof(reply), 0, (void *)&from, &from_length) != sizeof(reply) ||
            reply.sequence != wire_sequence ||
            !(backend = find_probed(from.sin_addr.s_addr, 0)) || backend->missed_rounds == 0)
            continue;
        backend->utilization_milli = ntohl(reply.utilization_milli);
        backend->capacity_milli = ntohl(reply.capacity_milli);
        backend->missed_rounds = 0;
        pending--;
    }
}

static void update_vips(int vip_fd, int backend_fd, int awfd_fd)
{
    __be32 addresses[MAX_BACKENDS_PER_VIP];
    struct vip_key vip, *previous = NULL;
    struct awfd_classes classes, current;
    struct backend_key key;
    struct vip_value value;
    struct backend backend;

    for (; !bpf_map_get_next_key(vip_fd, previous, &vip); previous = &vip) {
        if (bpf_map_lookup_elem(vip_fd, &vip, &value) || value.backend_count > MAX_BACKENDS_PER_VIP)
            continue;
        for (key = (struct backend_key){ .vip = vip }; key.slot < value.backend_count; key.slot++) {
            if (bpf_map_lookup_elem(backend_fd, &key, &backend))
                break;
            addresses[key.slot] = backend.address;
        }
        if (key.slot < value.backend_count)
            continue;

        if (!build_vip_classes(addresses, value.backend_count, &classes)) {
            bpf_map_delete_elem(awfd_fd, &vip);
            continue;
        }
        if (!bpf_map_lookup_elem(awfd_fd, &vip, &current) && !memcmp(&current, &classes, sizeof(classes)))
            continue;
        if (bpf_map_update_elem(awfd_fd, &vip, &classes, BPF_ANY))
            fprintf(stderr, "cannot write awfd_map: %s\n", strerror(errno));
    }
}

static void remove_stale_vips(int vip_fd, int awfd_fd)
{
    struct vip_key vip, kept, *previous = NULL;
    struct vip_value value;

    while (!bpf_map_get_next_key(awfd_fd, previous, &vip)) {
        if (bpf_map_lookup_elem(vip_fd, &vip, &value)) {
            bpf_map_delete_elem(awfd_fd, &vip);
            continue;
        }
        kept = vip;
        previous = &kept;
    }
}

int main(int argc, char **argv)
{
    static const struct option options[] = { { "static", no_argument, NULL, 's' }, {} };
    int option, vip_fd, backend_fd, awfd_fd, sock;

    while ((option = getopt_long(argc, argv, "m:i:", options, NULL)) != -1) {
        if (option == 'm')
            max_weight = atoi(optarg);
        else if (option == 'i')
            interval_ms = atoi(optarg);
        else if (option == 's')
            static_weights = 1;
        else
            break;
    }
    if (option != -1 || optind != argc || max_weight < 1 || max_weight > AWFD_MAX_WEIGHT || interval_ms < 1) {
        fputs(usage, stderr);
        return 1;
    }

    vip_fd = open_map("vip_map");
    backend_fd = open_map("backend_map");
    awfd_fd = open_map("awfd_map");
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (vip_fd < 0 || backend_fd < 0 || awfd_fd < 0 || sock < 0)
        return 1;

    for (__u32 sequence = 0;; sequence++) {
        long long round_end = now_ms() + interval_ms, rest_ms;

        probe_backends(sock, sequence, round_end - interval_ms / 2);
        update_vips(vip_fd, backend_fd, awfd_fd);
        remove_stale_vips(vip_fd, awfd_fd);
        if ((rest_ms = round_end - now_ms()) > 0)
            usleep(rest_ms * 1000);
    }
}
