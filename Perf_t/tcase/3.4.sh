#!/bin/bash
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

one_round() {
    local size=$1 s0 s1 u0 u1
    round_begin $TEST-$size $DURATION "test=$TEST variant=pmtu ip_size=$size pps=$PMTU_PPS raw_tool=$RAW_TOOL \
duration=$DURATION" || return 0
    reset_b
    s0=$(cmd b "$B_STATS")
    u0=$(cmd c "$C_UDP_IN")
    read_counters 0
    cpu_begin
    traffic raw df$size $PMTU_PPS $DURATION
    cpu_end
    read_counters 1
    round_end
    s1=$(cmd b "$B_STATS")
    u1=$(cmd c "$C_UDP_IN")
    delta_field "B frag_needed" frag_needed "$s0" "$s1"
    delta_field "B icmp_sent" icmp_sent "$s0" "$s1"
    delta "C udp_in (3 backend)" "$u0" "$u1"
}

t3_4() {
    local size
    on_c mode guarded
    on_c quota ${QUOTA[equal]} >/dev/null
    on_b mode xdp >/dev/null
    on_b bpf-stats on
    on_b feature pmtu on
    vip_route
    for rep in $(seq $REPS_TEST3); do
        idle_round $TEST-pmtu "test=$TEST variant=pmtu"
        for size in 1470 1490; do one_round $size; done
    done
    vip_route mtu lock $VIP_MTU
    on_b bpf-stats off
    restore
}

run_one 3.4 "$@"
