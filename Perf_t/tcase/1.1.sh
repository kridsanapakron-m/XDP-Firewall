#!/bin/bash
REPS=10
DURATION=60
IDLE_DURATION=10
LB_LIST="xdp ipvs nft ipt nginx"
UDP_POINTS="64:50000 64:100000 64:250000 64:500000 64:750000 64:1000000
            128:50000 128:100000 128:250000 128:500000
            512:50000 512:100000
            1024:50000 1024:100000"
source "$(dirname "$0")/run_lib.sh"

start_test 1.1 "$@"

for rep in $(seq $REPS); do
    for mode in $(select_lb $LB_LIST); do
        switch_lb $mode
        run_idle_round $TEST-$mode "test=$TEST mode=$mode"

        for point in $UDP_POINTS; do
            size=${point%:*} pps=${point#*:}
            begin_round $TEST-$mode-$size-$pps "test=$TEST mode=$mode size=$size pps=$pps \
link_bound=$(( pps * (size + 40) * 8 >= 950000000 )) $(flow_meta est $EST_PORTS)"
            reset_lb
            read_counters_begin
            read_cpu_begin
            run_traffic pktgen dst_mac=$LB_MAC dst=$VIP size=$size pps=$pps seconds=$DURATION
            read_cpu_end
            read_counters_end
        done
    done
done

restore
write_result
