#!/bin/bash
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

SCENARIO=1-0.5-0.25

one_round() {
    local variant=$1 level=$2 RESET_ARGS="algo $(variant_algo $1 $SCENARIO)" r0 r1
    on_c quota ${QUOTA[$SCENARIO]} >/dev/null
    round_begin $TEST-${variant/:/-}-web-1k-${level%:*} $HTTP_DURATION "test=$TEST mode=${variant%%:*} algo=${variant#*:} scenario=$SCENARIO workload=web-1k \
$(level_meta $SCENARIO web-1k $level)" || return 0
    reset_b
    r0=$(cmd c "$C_REQUESTS")
    read_counters 0
    cpu_begin
    traffic via_vip web-1k ${level#*:}
    cpu_end
    read_counters 1
    round_end
    r1=$(cmd c "$C_REQUESTS")
    delta_requests "$r0" "$r1"
}

t4_5() {
    local variant level
    check_test4 $SCENARIO
    for rep in $(seq $REPS_HTTP); do
        for variant in $TEST4_VARIANTS; do
            use_mode ${variant%%:*}
            for level in $(test4_levels $SCENARIO); do one_round $variant $level; done
        done
    done
    restore
}

run_one 4.5 "$@"
