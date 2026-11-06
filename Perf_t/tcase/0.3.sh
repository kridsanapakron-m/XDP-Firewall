#!/bin/bash
REPS=10
HTTP_DURATION=40
source "$(dirname "$0")/run_lib.sh"

start_test 0.3 "$@"

B_OFF_PATH=1
on_c mode direct

for rep in $(seq $REPS); do
    for scenario in $TEST4_SCENARIOS; do
        on_c quota ${QUOTA[$scenario]} >/dev/null
        begin_round $TEST-$scenario-web-1k "test=$TEST scenario=$scenario workload=web-1k level=sat $(http_meta)"
        reset_lb
        read_counters_begin
        read_cpu_begin
        run_traffic direct3 web-1k sat
        read_cpu_end
        read_counters_end
    done
done

restore
write_result
