#!/bin/bash
DURATION=${DURATION:-60}
IDLE_DURATION=${IDLE_DURATION:-60}
REPS_TEST3=${REPS_TEST3:-${REPS:-10}}
TEST35_FRAGS=${TEST35_FRAGS:-"1 2 3 4 5 6 7 8 9 10"}
TEST35_PPS=${TEST35_PPS:-100000}
TEST3_REST=${TEST3_REST:-10}
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

one_round() {
    local frags=$1 fwd0 fwd1 s0 s1 f0 f1
    round_begin $TEST-$frags $(( DURATION + TEST3_REST )) "test=$TEST variant=xdp fragment=on frags=$frags \
pps=$TEST35_PPS dps=$(( TEST35_PPS / frags )) profile=est flows=1000 duration=$DURATION" || return 0
    reset_b
    s0=$(cmd b "$B_STATS")
    f0=$(cmd c "$C_UDP_FRAG_IN")
    read_counters 0
    cpu_begin
    perf_begin
    traffic frag $frags $TEST35_PPS $DURATION
    perf_end
    cpu_end
    read_counters 1
    round_end
    s1=$(cmd b "$B_STATS")
    f1=$(cmd c "$C_UDP_FRAG_IN")
    fwd0=$(field xdp_redirect <<< "$s0") fwd1=$(field xdp_redirect <<< "$s1")
    delta "B ส่งต่อ (packet)" "$fwd0" "$fwd1"
    delta_field "B frag_hit" frag_hit "$s0" "$s1"
    delta_field "B frag_miss" frag_miss "$s0" "$s1"
    delta "C udp_frag_in (ประกอบได้)" "$f0" "$f1"
    per_unit packet $(( fwd1 - fwd0 ))
    per_unit datagram $(sent_of)
    sleep $TEST3_REST
}

t3_5() {
    local frags
    perf_start_check
    on_c mode guarded
    on_c quota ${QUOTA[equal]} >/dev/null
    on_b mode xdp >/dev/null
    on_b feature fragment on
    if [ -z "$PLAN" ]; then for frags in $TEST35_FRAGS; do frag_pcap $frags >/dev/null; done; fi
    for rep in $(seq $REPS_TEST3); do
        idle_perf $TEST-fragment "test=$TEST variant=xdp fragment=on"
        for frags in $TEST35_FRAGS; do one_round $frags; done
    done
    restore
}

run_one 3.5 "$@"
