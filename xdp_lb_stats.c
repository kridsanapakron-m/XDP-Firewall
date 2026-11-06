#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <string.h>

#include "xdp_lb_common.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define fail(...) (fprintf(stderr, __VA_ARGS__), fputc('\n', stderr), 1)

static const char *map_path = "/sys/fs/bpf/xdp_lb_test/maps/stats_map";

static const char *const stat_names[] = {
    "xdp_aborted", "xdp_drop", "xdp_pass", "xdp_tx", "xdp_redirect",
    "conn_hit", "conn_new", "conn_race", "awfd_dispatched",
    "frag_hit", "frag_miss", "frag_store_failed", "fib_failed",
    "frag_needed", "icmp_sent",
};
_Static_assert(ARRAY_SIZE(stat_names) == sizeof(struct lb_stats) / sizeof(__u64),
               "stat_names must name every counter of struct lb_stats");

int main(int argc, char **argv)
{
    int cpus = libbpf_num_possible_cpus(), fd = bpf_obj_get(map_path);
    struct lb_stats per_cpu[cpus > 0 ? cpus : 1];
    __u64 totals[ARRAY_SIZE(stat_names)] = { 0 };

    if (argc > 2 || (argc == 2 && strcmp(argv[1], "reset")))
        return fail("usage: xdp_lb_stats [reset]");
    if (cpus <= 0 || fd < 0)
        return fail("cannot open %s: %s", map_path, strerror(errno));
    if (argc == 2) {
        memset(per_cpu, 0, sizeof(per_cpu));
        return bpf_map_update_elem(fd, &(__u32){0}, per_cpu, BPF_ANY)
                   ? fail("cannot reset stats_map: %s", strerror(errno)) : 0;
    }
    if (bpf_map_lookup_elem(fd, &(__u32){0}, per_cpu))
        return fail("cannot read stats_map: %s", strerror(errno));
    for (int cpu = 0; cpu < cpus; cpu++)
        for (size_t index = 0; index < ARRAY_SIZE(totals); index++)
            totals[index] += ((__u64 *)&per_cpu[cpu])[index];
    for (size_t index = 0; index < ARRAY_SIZE(totals); index++)
        printf("%-18s %llu\n", stat_names[index], (unsigned long long)totals[index]);
    return 0;
}
