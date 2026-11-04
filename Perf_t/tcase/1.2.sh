#!/bin/bash
HTTP_DURATION=${HTTP_DURATION:-60}
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

one_round() {
    local mode=$1 load=$2 level=$3 r0 r1
    round_begin $TEST-$mode-$load-${level%:*} $HTTP_DURATION "test=$TEST mode=$mode workload=$load \
$(level_meta equal $load $level)" || return 0
    reset_b
    r0=$(cmd c "$C_REQUESTS")
    read_counters 0
    cpu_begin
    traffic via_vip $load ${level#*:}
    cpu_end
    read_counters 1
    round_end
    r1=$(cmd c "$C_REQUESTS")
    delta_requests "$r0" "$r1"
    show_cpu b
}

t1_2() {
    local mode load level
    need_c0 equal web-1k web-1k-close
    for rep in $(seq $REPS_HTTP); do
        for mode in $TEST1_MODES; do
            use_mode $mode
            idle_round $TEST-$mode "test=$TEST mode=$mode"
            for load in web-1k web-1k-close; do
                for level in $(levels equal $load "$TEST12_LEVELS") sat:sat; do one_round $mode $load $level; done
            done
        done
    done
    restore
}

run_one 1.2 "$@"
