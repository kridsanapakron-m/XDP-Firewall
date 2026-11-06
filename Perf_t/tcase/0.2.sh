#!/bin/bash
REPS=10
HTTP_DURATION=40
WORKLOADS="web-1k web-10k web-100k web-1m web-mix elephant"
source "$(dirname "$0")/run_lib.sh"

start_test 0.2 "$@"

B_OFF_PATH=1
on_c mode direct
on_c quota ${QUOTA[unequal]} >/dev/null

for rep in $(seq $REPS); do
    for load in $WORKLOADS; do
        begin_round $TEST-$load "test=$TEST scenario=unequal workload=$load level=sat streams=$STREAMS $(http_meta)"
        reset_lb
        read_counters_begin
        read_cpu_begin
        run_traffic direct3 $load sat
        read_cpu_end
        read_counters_end
    done
done

restore
write_result
