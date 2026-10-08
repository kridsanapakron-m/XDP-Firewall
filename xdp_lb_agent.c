#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "xdp_lb_common.h"

/*
 * Answers AWFD probes with the utilization U and capacity C of one backend,
 * read from the cgroup v2 directory its server runs in (the paper's DIPs report
 * load and processing time instead, Section IV-B). Runs in the backend's netns:
 *   nsenter --net=/var/run/netns/server_1 -- xdp_lb_agent 192.168.201.2 /sys/fs/cgroup/backend1
 * ip netns exec would remount /sys and hide /sys/fs/cgroup.
 */

static const char usage[] = "usage: xdp_lb_agent <backend_ip> <cgroup_dir>\n";

static const char *cgroup_dir;

static FILE *open_cgroup_file(const char *name)
{
    char path[512];

    snprintf(path, sizeof(path), "%s/%s", cgroup_dir, name);
    return fopen(path, "r");
}

/* CPU time the cgroup has used, from the first line of cpu.stat. */
static int read_usage_usec(unsigned long long *usage_usec)
{
    FILE *file = open_cgroup_file("cpu.stat");
    int found = file && fscanf(file, "usage_usec %llu", usage_usec) == 1;

    if (file)
        fclose(file);
    return found ? 0 : -1;
}

/* C in CPUs x1000 from cpu.max ("quota period"); "max" means every online CPU. */
static __u32 read_capacity_milli(void)
{
    FILE *file = open_cgroup_file("cpu.max");
    __u32 capacity_milli = sysconf(_SC_NPROCESSORS_ONLN) * AWFD_MILLI;
    unsigned long long period;
    char quota[32];

    if (file && fscanf(file, "%31s %llu", quota, &period) == 2 && strcmp(quota, "max") && period)
        capacity_milli = strtoull(quota, NULL, 10) * AWFD_MILLI / period;
    if (file)
        fclose(file);
    return capacity_milli;
}

static unsigned long long now_usec(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * 1000000ULL + now.tv_nsec / 1000;
}

/* U x1000 over the time since the previous probe; unmeasurable counts as full. */
static __u32 utilization_milli(unsigned long long used_usec, unsigned long long elapsed_usec,
                               __u32 capacity_milli)
{
    unsigned long long offered = elapsed_usec * capacity_milli / AWFD_MILLI;
    unsigned long long utilization = offered ? used_usec * AWFD_MILLI / offered : AWFD_MILLI;

    return utilization < AWFD_MILLI ? utilization : AWFD_MILLI;
}

int main(int argc, char **argv)
{
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(AWFD_AGENT_PORT) };
    unsigned long long last_usage_usec, last_time_usec;
    FILE *cpu_max;
    int sock;

    if (argc != 3 || inet_pton(AF_INET, argv[1], &address.sin_addr) != 1) {
        fputs(usage, stderr);
        return 1;
    }
    cgroup_dir = argv[2];
    cpu_max = open_cgroup_file("cpu.max");
    if (!cpu_max || read_usage_usec(&last_usage_usec)) {
        fprintf(stderr, "%s needs cpu.stat and cpu.max (cpu controller enabled)\n", cgroup_dir);
        return 1;
    }
    fclose(cpu_max);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0 || bind(sock, (void *)&address, sizeof(address))) {
        fprintf(stderr, "cannot bind %s:%d: %s\n", argv[1], AWFD_AGENT_PORT, strerror(errno));
        return 1;
    }
    last_time_usec = now_usec();

    for (;;) {
        struct sockaddr_in from;
        socklen_t from_length = sizeof(from);
        unsigned long long usage_usec, time_usec;
        struct awfd_probe_reply reply;
        __u32 capacity_milli;

        if (recvfrom(sock, &reply.sequence, sizeof(reply.sequence), 0, (void *)&from,
                     &from_length) != sizeof(reply.sequence) || read_usage_usec(&usage_usec))
            continue;
        time_usec = now_usec();
        capacity_milli = read_capacity_milli();
        reply.utilization_milli = htonl(utilization_milli(usage_usec - last_usage_usec,
                                                          time_usec - last_time_usec,
                                                          capacity_milli));
        reply.capacity_milli = htonl(capacity_milli);
        last_usage_usec = usage_usec;
        last_time_usec = time_usec;
        sendto(sock, &reply, sizeof(reply), 0, (void *)&from, from_length);
    }
}
