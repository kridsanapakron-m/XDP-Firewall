#!/bin/bash
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

one_round() {
    local count=$1 pattern=$2 dst=$MULTI_VIP_FIRST dst_count=$1 rx0 rx1 lk
    if [ $pattern = last ]; then dst=$(ip_add $MULTI_VIP_FIRST $(( count - 1 ))) dst_count=1; fi
    round_begin $TEST-$count-$pattern $DURATION "test=$TEST mode=ipt vips=$count pattern=$pattern pps=$TEST2_PPS \
size=64 $(flow_meta new $NEW_PORTS)" || return 0
    reset_b
    rx0=$(cmd b "$B_NIC/rx_packets")
    read_counters 0
    cpu_begin
    traffic traced pktgen dst_mac=$LB_MAC dst=$dst dst_count=$dst_count size=64 pps=$TEST2_PPS seconds=$DURATION \
        ports=$NEW_PORTS
    cpu_end
    read_counters 1
    round_end
    rx1=$(cmd b "$B_NIC/rx_packets")
    lk=$(cmd a "cat $out.lookup")
    delta "B rx_packets" "$rx0" "$rx1"
    ratio "ns ต่อครั้ง (lookup_ns ÷ calls)" 0 "$(field lookup_ns <<< "$lk")" 0 "$(field lookup_calls <<< "$lk")"
    ratio "ครั้งต่อ packet (calls ÷ rx)" 0 "$(field lookup_calls <<< "$lk")" "$rx0" "$rx1"
}

t2_3() {
    local count pattern
    on_b bpf-stats on
    for rep in $(seq $REPS_TEST2); do
        for count in $VIP_COUNTS; do
            use_mode ipt $count
            for pattern in spread last; do one_round $count $pattern; done
        done
    done
    on_b bpf-stats off
    restore
}

run_one 2.3 "$@"
