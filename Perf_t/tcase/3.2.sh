#!/bin/bash
DURATION=${DURATION:-60}
IDLE_DURATION=${IDLE_DURATION:-60}
REPS_TEST3=${REPS_TEST3:-${REPS:-10}}
TEST32_PPS=${TEST32_PPS:-"100000 200000 300000 400000 500000 600000 700000 800000 900000 1000000"}
TEST3_REST=${TEST3_REST:-10}
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

one_round() {
    local fragment=$1 pps=$2 fwd0 fwd1
    round_begin $TEST-$fragment-64-$pps $(( DURATION + TEST3_REST )) "test=$TEST variant=xdp fragment=$fragment lb_cores=1 \
size=64 pps=$pps $(flow_meta est $EST_PORTS)" || return 0
    reset_one_core
    fwd0=$(forwarded xdp)
    read_counters 0
    cpu_begin
    core0_begin
    traffic pktgen dst_mac=$LB_MAC dst=$VIP size=64 pps=$pps seconds=$DURATION
    core0_end
    cpu_end
    read_counters 1
    round_end
    fwd1=$(forwarded xdp)
    delta "B ส่งต่อ" "$fwd0" "$fwd1"
    per_unit0 packet $(( fwd1 - fwd0 ))
    sleep $TEST3_REST
}

t3_2() {
    local fragment pps
    one_core_start
    on_c mode guarded
    on_c quota ${QUOTA[equal]} >/dev/null
    on_b mode xdp >/dev/null
    for rep in $(seq $REPS_TEST3); do
        for fragment in off on; do
            on_b feature fragment $fragment
            idle_one_core $TEST-$fragment "test=$TEST variant=xdp fragment=$fragment lb_cores=1"
            for pps in $TEST32_PPS; do one_round $fragment $pps; done
        done
    done
    restore
}

run_one 3.2 "$@"
