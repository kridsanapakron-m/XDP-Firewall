#!/bin/bash
HTTP_DURATION=${HTTP_DURATION:-60}
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

one_round() {
    local mode=$1 rx0 rx1 by0 by1
    round_begin $TEST-$mode $HTTP_DURATION "test=$TEST mode=$mode workload=elephant streams=$STREAMS \
http_duration=$HTTP_DURATION" || return 0
    reset_b
    rx0=$(cmd b "$B_NIC/rx_packets")
    by0=$(cmd b "$B_NIC/rx_bytes")
    read_counters 0
    cpu_begin
    traffic via_vip elephant sat
    cpu_end
    read_counters 1
    round_end
    rx1=$(cmd b "$B_NIC/rx_packets")
    by1=$(cmd b "$B_NIC/rx_bytes")
    delta "B rx_packets" "$rx0" "$rx1"
    delta "B rx_bytes" "$by0" "$by1"
    ratio "B byte ต่อ packet" "$by0" "$by1" "$rx0" "$rx1"
    show_cpu b
}

t1_3() {
    local mode
    for rep in $(seq $REPS_HTTP); do
        for mode in $TEST1_MODES; do
            use_mode $mode
            idle_round $TEST-$mode "test=$TEST mode=$mode"
            one_round $mode
        done
    done
    restore
}

run_one 1.3 "$@"
