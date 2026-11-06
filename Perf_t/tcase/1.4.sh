#!/bin/bash
REPS=10
HTTP_DURATION=60
LB_LIST="direct xdp ipvs nft ipt nginx haproxy"
RATE=1000
source "$(dirname "$0")/run_lib.sh"

start_test 1.4 "$@"

for rep in $(seq $REPS); do
    for mode in $(select_lb $LB_LIST); do
        if [ $mode = direct ]; then
            B_OFF_PATH=1
            on_c mode direct
        else
            B_OFF_PATH=
            switch_lb $mode
        fi

        begin_round $TEST-$mode "test=$TEST mode=$mode workload=web-1k rate=$RATE $(http_meta)"
        reset_lb
        read_counters_begin
        read_cpu_begin
        if [ $mode = direct ]; then
            run_traffic direct3 web-1k $RATE
        else
            run_traffic via_vip web-1k $RATE
        fi
        read_cpu_end
        read_counters_end
    done
done

restore
write_result
