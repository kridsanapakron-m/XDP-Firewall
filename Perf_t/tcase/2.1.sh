#!/bin/bash
REPS=10
DURATION=20
PPS=40000
VIP_COUNTS="1 10 100 1000"
source "$(dirname "$0")/run_lib.sh"

start_test 2.1 "$@"
on_b bpf-stats on

for rep in $(seq $REPS); do
    for count in $VIP_COUNTS; do
        switch_lb xdp $count

        for pattern in spread last; do
            dst=$MULTI_VIP_FIRST dst_count=$count
            if [ $pattern = last ]; then dst=$(ip_add $MULTI_VIP_FIRST $(( count - 1 ))) dst_count=1; fi

            begin_round $TEST-$count-$pattern "test=$TEST mode=xdp vips=$count pattern=$pattern pps=$PPS \
size=64 $(flow_meta new $NEW_PORTS)"
            reset_lb
            read_counters_begin
            read_cpu_begin
            run_traffic traced pktgen dst_mac=$LB_MAC dst=$dst dst_count=$dst_count size=64 pps=$PPS seconds=$DURATION \
                ports=$NEW_PORTS
            read_cpu_end
            read_counters_end
        done
    done
done

on_b bpf-stats off
restore
write_result
