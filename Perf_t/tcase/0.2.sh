#!/bin/bash
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

one_round() {
    local load=$1 r0 r1
    round_begin $TEST-$load $HTTP_DURATION "test=$TEST scenario=unequal workload=$load level=sat streams=$STREAMS $(http_meta)" ||
        return 0
    reset_b
    r0=$(cmd c "$C_REQUESTS")
    read_counters 0
    cpu_begin
    traffic direct3 $load sat
    cpu_end
    read_counters 1
    round_end
    r1=$(cmd c "$C_REQUESTS")
    delta_requests "$r0" "$r1"
    show_cpu c
}

t0_2() {
    local load B_OFF_PATH=1
    on_c mode direct
    on_c quota ${QUOTA[unequal]} >/dev/null
    for rep in $(seq $REPS_HTTP); do
        for load in $(web_loads) elephant; do one_round $load; done
    done
    restore
}

run_one 0.2 "$@"
