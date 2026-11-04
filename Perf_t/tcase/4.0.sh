#!/bin/bash
TEST40_SINGLE=${TEST40_SINGLE:-"40 20 10"}
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

splits_of() { if [ $(tr ' ' '\n' <<< "${QUOTA[$1]}" | sort -u | wc -l) = 1 ]; then echo fit; else echo fit equal; fi; }

split_direct() {
    if [ $2 = fit ] && [ "$(splits_of $1)" = "fit equal" ]; then direct3 web-1k $3 "${QUOTA[$1]//%/}"; else direct3 web-1k $3; fi
}

one_round() {
    local scenario=$1 split=$2 level=$3 r0 r1
    on_c quota ${QUOTA[$scenario]} >/dev/null
    round_begin $TEST-$scenario-$split-web-1k-${level%:*} $HTTP_DURATION "test=$TEST baseline=$split scenario=$scenario \
workload=web-1k $(level_meta $scenario web-1k $level)" || return 0
    reset_b
    r0=$(cmd c "$C_REQUESTS")
    read_counters 0
    cpu_begin
    traffic split_direct $scenario $split ${level#*:}
    cpu_end
    read_counters 1
    round_end
    r1=$(cmd c "$C_REQUESTS")
    delta_requests "$r0" "$r1"
}

dynamic_round() {
    local level=$1 HTTP_DURATION=$HTTP_DURATION_DYNAMIC
    on_c quota ${QUOTA[1-1-1]} >/dev/null
    round_begin $TEST-dynamic-equal-web-1k-${level%:*} $HTTP_DURATION "test=$TEST baseline=equal scenario=dynamic \
workload=web-1k $(level_meta 1-1-0.5 web-1k $level)" || return 0
    reset_b
    read_counters 0
    cpu_begin
    traffic dynamic direct3 web-1k ${level#*:}
    cpu_end
    read_counters 1
    round_end
}

single() { http $(backend_ip 1) 1k sat $CONNS; }
single_round() {
    local quota=$1
    on_c quota "$quota% $quota% $quota%" >/dev/null
    round_begin $TEST-single-$quota $HTTP_DURATION "test=$TEST baseline=single quota_pct=$quota workload=web-1k \
level=sat $(http_meta)" || return 0
    reset_b
    read_counters 0
    cpu_begin
    traffic single
    cpu_end
    read_counters 1
    round_end
}

t4_0() {
    local scenario split level quota B_OFF_PATH=1
    for scenario in $TEST4_SCENARIOS; do need_c0 $scenario web-1k; done
    on_c mode direct
    for rep in $(seq $REPS_HTTP); do
        for scenario in $TEST4_SCENARIOS; do
            for split in $(splits_of $scenario); do
                for level in $(levels $scenario web-1k "$TEST4_LEVELS"); do one_round $scenario $split $level; done
            done
        done
        for level in $(levels 1-1-0.5 web-1k "$TEST4_LEVELS"); do dynamic_round $level; done
        for quota in $TEST40_SINGLE; do single_round $quota; done
    done
    restore
}

run_one 4.0 "$@"
