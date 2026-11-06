#!/bin/bash
REPS=10
DURATION=20
IDLE_DURATION=10
PPS=50000
source "$(dirname "$0")/run_lib.sh"

start_test 3.4 "$@"
on_c mode guarded
on_c quota ${QUOTA[equal]} >/dev/null
on_b mode xdp >/dev/null
on_b bpf-stats on
on_b feature pmtu on
vip_route

for rep in $(seq $REPS); do
    run_idle_round $TEST-pmtu "test=$TEST variant=pmtu"

    for size in 1470 1490; do
        begin_round $TEST-$size "test=$TEST variant=pmtu ip_size=$size pps=$PPS raw_tool=hping3 duration=$DURATION"
        reset_lb
        read_counters_begin
        read_cpu_begin
        run_traffic raw df$size $PPS $DURATION
        read_cpu_end
        read_counters_end
    done
done

vip_route mtu lock $VIP_MTU
on_b bpf-stats off
restore
write_result
