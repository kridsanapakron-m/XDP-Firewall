#!/bin/bash
DURATION=${DURATION:-60}
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

udp_points() {
    local pps size
    if [ -n "${UDP_POINTS:-}" ]; then
        printf '%s\n' $UDP_POINTS
        return
    fi
    for pps in $PPS_LADDER $STRESS_PPS; do echo 64:$pps; done
    for size in $SIZES; do echo $size:$SIZE_SWEEP_PPS; done
}

one_round() {
    local mode=$1 size=$2 pps=$3 rx0 rx1 miss0 miss1 fwd0 fwd1 udp0 udp1
    round_begin $TEST-$mode-$size-$pps $DURATION "test=$TEST mode=$mode size=$size pps=$pps \
link_bound=$(( pps * (size + 40) * 8 >= 950000000 )) $(flow_meta est $EST_PORTS)" || return 0
    reset_b
    rx0=$(cmd b "$B_NIC/rx_packets")
    miss0=$(cmd b "$B_NIC/rx_missed_errors")
    fwd0=$(forwarded $mode)
    udp0=$(cmd c "$C_UDP_IN")
    read_counters 0
    cpu_begin
    traffic pktgen dst_mac=$LB_MAC dst=$VIP size=$size pps=$pps seconds=$DURATION
    cpu_end
    read_counters 1
    round_end
    rx1=$(cmd b "$B_NIC/rx_packets")
    miss1=$(cmd b "$B_NIC/rx_missed_errors")
    fwd1=$(forwarded $mode)
    udp1=$(cmd c "$C_UDP_IN")
    delta "B rx_packets" "$rx0" "$rx1"
    delta "B rx_missed_errors" "$miss0" "$miss1"
    delta "B ส่งต่อ" "$fwd0" "$fwd1"
    delta "C udp_in (3 backend)" "$udp0" "$udp1"
    show_cpu b
}

t1_1() {
    local mode point
    for rep in $(seq $REPS_UDP); do
        for mode in $TEST1_MODES; do
            if [ $mode = haproxy ]; then continue; fi
            use_mode $mode
            idle_round $TEST-$mode "test=$TEST mode=$mode"
            for point in $(udp_points | awk '!seen[$0]++'); do one_round $mode ${point%:*} ${point#*:}; done
        done
    done
    restore
}

run_one 1.1 "$@"
