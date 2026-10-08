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

#include "xdp_lb_awfd_common.h"

/*
 * AWFD controller (Aghdai et al., "Spotlight", Section IV-C). Every interval it
 * polls the agent of each backend, turns A = (1 - U) * C into weights and
 * priority classes, and writes awfd_map, of which it is the only writer.
 */

#define MISSED_ROUNDS_LIMIT 3
#define fail(...) (fprintf(stderr, __VA_ARGS__), fputc('\n', stderr), -1)

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
    return fd < 0 ? fail("cannot open %s: %s", path, strerror(errno)) : fd;
}

/* A backend seen for the first time is probed from the next round on. */
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

/*
 * A = (1 - U) * C (Table I), or C alone with --static. A backend that misses
 * replies keeps its last answer (Section IV-D5 applied to probes); after
 * MISSED_ROUNDS_LIMIT rounds, or before any answer, it counts as full (our
 * addition), and so does a utilization of 100% or more.
 */
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

/*
 * Weights w = floor(m * A / max A) (Section III-B1), then classes B_1..B_m with
 * B_0 left out (footnote 2) and the Stage I ranges of eq. 1 laid end to end
 * (Figure 5). Classes above m stay empty, so their range_end equals weight_sum
 * and the kernel never needs m. Returns max A, 0 when every backend is in B_0.
 */
static __u32 build_vip_classes(const __be32 *addresses, int count, __u32 *weights,
                               struct awfd_classes *classes)
{
    __u32 available[MAX_BACKENDS_PER_VIP], max_available = 0;

    for (int slot = 0; slot < count; slot++) {
        available[slot] = backend_available(find_probed(addresses[slot], 1));
        if (available[slot] > max_available)
            max_available = available[slot];
    }

    *classes = (struct awfd_classes){};
    for (int slot = 0; slot < count; slot++) {
        __u32 class;

        weights[slot] = max_available ? (__u64)max_weight * available[slot] / max_available : 0;
        if (!weights[slot])
            continue;
        class = weights[slot] - 1;
        classes->members[class][classes->class_size[class]++] = slot;
    }
    for (__u32 class = 0; class < AWFD_MAX_WEIGHT; class++) {
        classes->weight_sum += (class + 1) * classes->class_size[class];
        classes->range_end[class] = classes->weight_sum;
    }
    return max_available;
}

/* Sends one probe per known backend and collects replies until the deadline. */
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

/* Reads the backends of one VIP; returns their count or -1. */
static int read_backends(int vip_fd, int backend_fd, const struct vip_key *vip, __be32 *addresses)
{
    struct backend_key key = { .vip = *vip };
    struct vip_value value;
    struct backend backend;

    if (bpf_map_lookup_elem(vip_fd, vip, &value) || value.backend_count > MAX_BACKENDS_PER_VIP)
        return -1;
    for (; key.slot < value.backend_count; key.slot++) {
        if (bpf_map_lookup_elem(backend_fd, &key, &backend))
            return -1;
        addresses[key.slot] = backend.address;
    }
    return value.backend_count;
}

static void print_vip(const struct vip_key *vip, const __u32 *weights, int count)
{
    char address[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &vip->address, address, sizeof(address));
    printf("%s:%u/%s weights", address, ntohs(vip->port),
           vip->protocol == IPPROTO_UDP ? "udp" : "tcp");
    for (int slot = 0; slot < count; slot++)
        printf(" %u", weights[slot]);
    printf("\n");
    fflush(stdout);
}

static void update_vip(int awfd_fd, const struct vip_key *vip, const __be32 *addresses, int count)
{
    __u32 weights[MAX_BACKENDS_PER_VIP];
    struct awfd_classes classes, current;

    /* Every backend in B_0: drop the classes so the kernel uses ECMP (our addition). */
    if (!build_vip_classes(addresses, count, weights, &classes)) {
        if (!bpf_map_delete_elem(awfd_fd, vip))
            print_vip(vip, weights, count);
        return;
    }

    /* Only VIPs whose classes changed are written (Section IV-C1). */
    if (!bpf_map_lookup_elem(awfd_fd, vip, &current) && !memcmp(&current, &classes, sizeof(classes)))
        return;
    if (bpf_map_update_elem(awfd_fd, vip, &classes, BPF_ANY))
        fprintf(stderr, "cannot write awfd_map: %s\n", strerror(errno));
    else
        print_vip(vip, weights, count);
}

static void update_vips(int vip_fd, int backend_fd, int awfd_fd)
{
    __be32 addresses[MAX_BACKENDS_PER_VIP];
    struct vip_key vip, *previous = NULL;
    int count;

    for (; !bpf_map_get_next_key(vip_fd, previous, &vip); previous = &vip)
        if ((count = read_backends(vip_fd, backend_fd, &vip, addresses)) > 0)
            update_vip(awfd_fd, &vip, addresses, count);
}

/* Classes of VIPs that left vip_map are removed (our addition). */
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
    int option, invalid = 0, vip_fd, backend_fd, awfd_fd, sock;

    while ((option = getopt_long(argc, argv, "m:i:", options, NULL)) != -1) {
        if (option == 'm')
            max_weight = atoi(optarg);
        else if (option == 'i')
            interval_ms = atoi(optarg);
        else if (option == 's')
            static_weights = 1;
        else
            invalid = 1;
    }
    if (invalid || optind != argc || max_weight < 1 || max_weight > AWFD_MAX_WEIGHT || interval_ms < 1) {
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
