#!/bin/bash
DURATION=${DURATION:-60}
IDLE_DURATION=${IDLE_DURATION:-60}
REPS_UDP=${REPS_UDP:-${REPS:-5}}
TEST1_MODES=${TEST1_MODES:-"ipvs nft ipt nginx xdp"}
TEST16_PPS=${TEST16_PPS:-"100000 200000 300000 400000 500000 600000 700000 800000 900000 1000000"}
TEST16_REST=${TEST16_REST:-10}
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

one_round() {
    local mode=$1 pps=$2 fwd0 fwd1
    round_begin $TEST-$mode-64-$pps $(( DURATION + TEST16_REST )) "test=$TEST mode=$mode size=64 pps=$pps lb_cores=1 \
link_bound=$(( pps * (64 + 40) * 8 >= 950000000 )) $(flow_meta est $EST_PORTS)" || return 0
    reset_one_core
    fwd0=$(forwarded $mode)
    read_counters 0
    cpu_begin
    core0_begin
    traffic pktgen dst_mac=$LB_MAC dst=$VIP size=64 pps=$pps seconds=$DURATION
    core0_end
    cpu_end
    read_counters 1
    round_end
    fwd1=$(forwarded $mode)
    delta "B ส่งต่อ" "$fwd0" "$fwd1"
    per_unit0 "packet ที่ส่งต่อ" $(( fwd1 - fwd0 ))
    sleep $TEST16_REST
}

t1_6() {
    local mode pps
    one_core_start
    for rep in $(seq $REPS_UDP); do
        for mode in $TEST1_MODES; do
            if [ $mode = haproxy ]; then continue; fi
            use_mode $mode
            idle_one_core $TEST-$mode "test=$TEST mode=$mode lb_cores=1"
            for pps in $TEST16_PPS; do one_round $mode $pps; done
        done
    done
    restore
}

run_one 1.6 "$@"
