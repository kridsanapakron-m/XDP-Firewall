#!/bin/bash
REPS=10
DURATION=20
IDLE_DURATION=10
PPS_LIST="500000 100000"
source "$(dirname "$0")/run_lib.sh"

start_test 3.1 "$@"

for rep in $(seq $REPS); do
    for variant in xdp-hash xdp-awfd; do
        on_c mode guarded
        on_c quota ${QUOTA[equal]} >/dev/null
        on_b mode ${variant%-awfd} >/dev/null
        on_b bpf-stats on
        RESET_ARGS=""
        if [ $variant = xdp-awfd ]; then RESET_ARGS="algo $(variant_algo xdp:awfd4s)"; fi
        run_idle_round $TEST-$variant "test=$TEST variant=$variant"

        for profile in est new; do
            for pps in $PPS_LIST; do
                begin_round $TEST-$variant-$profile-$pps "test=$TEST variant=$variant size=64 pps=$pps \
$(flow_meta $profile $(ports_of $profile))"
                reset_lb
                read_counters_begin
                read_cpu_begin
                run_traffic pktgen size=64 pps=$pps seconds=$DURATION ports=$(ports_of $profile) dst_mac=$LB_MAC dst=$VIP
                read_cpu_end
                read_counters_end
            done
        done
    done
done

on_b bpf-stats off
restore
write_result
