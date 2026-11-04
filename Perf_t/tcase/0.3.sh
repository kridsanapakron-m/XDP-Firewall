#!/bin/bash
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

one_round() {
    local scenario=$1 r0 r1
    on_c quota ${QUOTA[$scenario]} >/dev/null
    round_begin $TEST-$scenario-web-1k $HTTP_DURATION "test=$TEST scenario=$scenario workload=web-1k level=sat $(http_meta)" ||
        return 0
    reset_b
    r0=$(cmd c "$C_REQUESTS")
    read_counters 0
    cpu_begin
    traffic direct3 web-1k sat
    cpu_end
    read_counters 1
    round_end
    r1=$(cmd c "$C_REQUESTS")
    delta_requests "$r0" "$r1"
    show_cpu c
}

t0_3() {
    local scenario B_OFF_PATH=1
    on_c mode direct
    for rep in $(seq $REPS_HTTP); do
        for scenario in $TEST4_SCENARIOS; do one_round $scenario; done
    done
    restore
}

run_one 0.3 "$@"
