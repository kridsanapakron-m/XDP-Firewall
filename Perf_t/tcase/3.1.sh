#!/bin/bash
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

one_round() {
    local variant=$VARIANT profile=$1 pps=$2 p0 p1 s0 s1
    shift 2
    round_begin $TEST-$variant-$profile-$pps $DURATION "test=$TEST variant=$variant size=64 pps=$pps \
$(flow_meta $profile $(ports_of $profile) ${threads:-})" || return 0
    reset_b
    p0=$(cmd b "$B_PROG")
    s0=$(cmd b "$B_STATS")
    read_counters 0
    cpu_begin
    traffic pktgen size=64 pps=$pps seconds=$DURATION ports=$(ports_of $profile) "$@"
    cpu_end
    read_counters 1
    round_end
    p1=$(cmd b "$B_PROG")
    s1=$(cmd b "$B_STATS")
    delta_field "B run_cnt" run_cnt "$p0" "$p1"
    delta_field "B run_time_ns" run_time_ns "$p0" "$p1"
    ratio "ns ต่อ packet (xdp_ns)" "$(field run_time_ns <<< "$p0")" "$(field run_time_ns <<< "$p1")" \
        "$(field run_cnt <<< "$p0")" "$(field run_cnt <<< "$p1")"
    delta_field "B conn_new" conn_new "$s0" "$s1"
    delta_field "B conn_hit" conn_hit "$s0" "$s1"
    delta_field "B awfd_dispatched" awfd_dispatched "$s0" "$s1"
}

points() {
    local profile pps
    for profile in est new; do
        for pps in $TEST3_PPS; do one_round $profile $pps "$@"; done
    done
}

t3_1() {
    local VARIANT RESET_ARGS
    for rep in $(seq $REPS_TEST3); do
        for VARIANT in xdp-hash xdp xdp-awfd; do
            on_c mode guarded
            on_c quota ${QUOTA[equal]} >/dev/null
            on_b mode ${VARIANT%-awfd} >/dev/null
            on_b bpf-stats on
            RESET_ARGS=""
            if [ $VARIANT = xdp-awfd ]; then RESET_ARGS="algo awfd 4 500"; fi
            idle_round $TEST-$VARIANT "test=$TEST variant=$VARIANT"
            points dst_mac=$LB_MAC dst=$VIP
        done
    done
    on_b bpf-stats off
    restore
}

run_one 3.1 "$@"
