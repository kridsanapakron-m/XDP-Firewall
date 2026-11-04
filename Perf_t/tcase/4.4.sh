#!/bin/bash
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

BEFORE=1-1-1
AFTER=1-1-0.5

one_round() {
    local variant=$1 level=$2 RESET_ARGS="algo $(variant_algo $1 $BEFORE)" r0 r1
    on_c quota ${QUOTA[$BEFORE]} >/dev/null
    round_begin $TEST-${variant/:/-}-web-1k-${level%:*} $HTTP_DURATION "test=$TEST mode=${variant%%:*} algo=${variant#*:} scenario=dynamic workload=web-1k \
$(level_meta $AFTER web-1k $level)" || return 0
    reset_b
    r0=$(cmd c "$C_REQUESTS")
    read_counters 0
    cpu_begin
    traffic dynamic via_vip web-1k ${level#*:}
    cpu_end
    read_counters 1
    round_end
    r1=$(cmd c "$C_REQUESTS")
    delta_requests "$r0" "$r1"
}

t4_4() {
    local variant level HTTP_DURATION=$HTTP_DURATION_DYNAMIC
    check_test4 $AFTER
    for rep in $(seq $REPS_HTTP); do
        for variant in $TEST4_VARIANTS; do
            use_mode ${variant%%:*}
            for level in $(test4_levels $AFTER); do one_round $variant $level; done
        done
    done
    restore
}

run_one 4.4 "$@"
