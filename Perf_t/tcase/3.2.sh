#!/bin/bash
REPS=10
DURATION=60
IDLE_DURATION=60
REST=10
PPS_LIST="100000 200000 300000 400000 500000 600000 700000 800000 900000 1000000"
source "$(dirname "$0")/run_lib.sh"

start_test 3.2 "$@"
prepare_one_core
on_c mode guarded
on_c quota ${QUOTA[equal]} >/dev/null
on_b mode xdp >/dev/null

for rep in $(seq $REPS); do
    for fragment in off on; do
        on_b feature fragment $fragment
        run_idle_one_core $TEST-$fragment "test=$TEST variant=xdp fragment=$fragment lb_cores=1"

        for pps in $PPS_LIST; do
            begin_round $TEST-$fragment-64-$pps "test=$TEST variant=xdp fragment=$fragment lb_cores=1 \
size=64 pps=$pps $(flow_meta est $EST_PORTS)"
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
