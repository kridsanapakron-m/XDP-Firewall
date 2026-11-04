#!/bin/bash
HTTP_DURATION=${HTTP_DURATION:-60}
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

one_round() {
    local mode=$1
    round_begin $TEST-$mode $HTTP_DURATION "test=$TEST mode=$mode workload=web-1k rate=$LAT_RATE $(http_meta)" || return 0
    reset_b
    read_counters 0
    cpu_begin
    if [ $mode = direct ]; then traffic direct3 web-1k $LAT_RATE; else traffic via_vip web-1k $LAT_RATE; fi
    cpu_end
    read_counters 1
    round_end
    show_cpu b
}

t1_4() {
    local mode B_OFF_PATH
    for rep in $(seq $REPS_HTTP); do
        for mode in direct $TEST1_MODES; do
            if [ $mode = direct ]; then
                B_OFF_PATH=1
                on_c mode direct
            else
                B_OFF_PATH=
                use_mode $mode
            fi
            one_round $mode
        done
    done
    restore
}

run_one 1.4 "$@"
