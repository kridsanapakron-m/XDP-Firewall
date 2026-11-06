#!/bin/bash
REPS=10
DURATION=60
IDLE_DURATION=60
REST=10
LB_LIST="ipvs nft ipt nginx xdp"
PPS_LIST="100000 200000 300000 400000 500000 600000 700000 800000 900000 1000000"
NGINX_LOW_PPS="10000 20000 30000 40000 50000 60000 70000 80000 90000"
source "$(dirname "$0")/run_lib.sh"

start_test 1.6 "$@"
prepare_one_core

for rep in $(seq $REPS); do
    for mode in $(select_lb $LB_LIST); do
        switch_lb $mode
        run_idle_one_core $TEST-$mode "test=$TEST mode=$mode lb_cores=1"

        pps_list=$PPS_LIST
        if [ $mode = nginx ]; then pps_list="$NGINX_LOW_PPS $PPS_LIST"; fi

        for pps in $pps_list; do
            begin_round $TEST-$mode-64-$pps "test=$TEST mode=$mode size=64 pps=$pps lb_cores=1 \
link_bound=$(( pps * (64 + 40) * 8 >= 950000000 )) $(flow_meta est $EST_PORTS)"
            reset_lb_one_core
            read_counters_begin
            read_cpu_begin
            read_core0_begin
            run_traffic pktgen dst_mac=$LB_MAC dst=$VIP size=64 pps=$pps seconds=$DURATION
            read_core0_end
            read_cpu_end
            read_counters_end
            sleep $REST
        done
    done
done

restore
write_result
