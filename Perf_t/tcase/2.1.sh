#!/bin/bash
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

one_round() {
    local count=$1 pattern=$2 dst=$MULTI_VIP_FIRST dst_count=$1 p0 p1 s0 s1
    if [ $pattern = last ]; then dst=$(ip_add $MULTI_VIP_FIRST $(( count - 1 ))) dst_count=1; fi
    round_begin $TEST-$count-$pattern $DURATION "test=$TEST mode=xdp vips=$count pattern=$pattern pps=$TEST2_PPS \
size=64 $(flow_meta new $NEW_PORTS)" || return 0
    reset_b
    p0=$(cmd b "$B_PROG")
    s0=$(cmd b "$B_STATS")
    read_counters 0
    cpu_begin
    traffic traced pktgen dst_mac=$LB_MAC dst=$dst dst_count=$dst_count size=64 pps=$TEST2_PPS seconds=$DURATION \
        ports=$NEW_PORTS
    cpu_end
    read_counters 1
    round_end
    p1=$(cmd b "$B_PROG")
    s1=$(cmd b "$B_STATS")
    delta_field "B run_cnt" run_cnt "$p0" "$p1"
    delta_field "B run_time_ns" run_time_ns "$p0" "$p1"
    ratio "ns ต่อ packet (ทั้งโปรแกรม)" "$(field run_time_ns <<< "$p0")" "$(field run_time_ns <<< "$p1")" \
        "$(field run_cnt <<< "$p0")" "$(field run_cnt <<< "$p1")"
    delta_field "B conn_new" conn_new "$s0" "$s1"
}

t2_1() {
    local count pattern
    on_b bpf-stats on
    for rep in $(seq $REPS_TEST2); do
        for count in $VIP_COUNTS; do
            use_mode xdp $count
            for pattern in spread last; do one_round $count $pattern; done
        done
    done
    on_b bpf-stats off
    restore
}

run_one 2.1 "$@"
