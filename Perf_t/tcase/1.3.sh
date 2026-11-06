#!/bin/bash
REPS=10
HTTP_DURATION=60
IDLE_DURATION=10
LB_LIST="xdp ipvs nft ipt nginx haproxy"
source "$(dirname "$0")/run_lib.sh"

start_test 1.3 "$@"

for rep in $(seq $REPS); do
    for mode in $(select_lb $LB_LIST); do
        switch_lb $mode
        run_idle_round $TEST-$mode "test=$TEST mode=$mode"

        begin_round $TEST-$mode "test=$TEST mode=$mode workload=elephant streams=$STREAMS http_duration=$HTTP_DURATION"
        reset_lb
        read_counters_begin
        read_cpu_begin
        run_traffic via_vip elephant sat
        read_cpu_end
        read_counters_end
    done
done

restore
write_result
