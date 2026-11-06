#!/bin/bash
REPS=10
HTTP_DURATION=40
DYNAMIC_DURATION=60
TEST4_LEVELS="50 60 70 80"
SINGLE_QUOTAS="40 20 10"
source "$(dirname "$0")/run_lib.sh"

splits_of() { if [ $(tr ' ' '\n' <<< "${QUOTA[$1]}" | sort -u | wc -l) = 1 ]; then echo fit; else echo fit equal; fi; }

split_direct() {
    if [ $2 = fit ] && [ "$(splits_of $1)" = "fit equal" ]; then direct3 web-1k $3 "${QUOTA[$1]//%/}"; else direct3 web-1k $3; fi
}

single() { http $(backend_ip 1) 1k sat $CONNS; }

start_test 4.0 "$@"
for scenario in $TEST4_SCENARIOS; do need_c0 $scenario web-1k; done

B_OFF_PATH=1
on_c mode direct

for rep in $(seq $REPS); do
    for scenario in $TEST4_SCENARIOS; do
        for split in $(splits_of $scenario); do
            for level in $(levels $scenario web-1k "$TEST4_LEVELS"); do
                on_c quota ${QUOTA[$scenario]} >/dev/null
                begin_round $TEST-$scenario-$split-web-1k-${level%:*} "test=$TEST baseline=$split scenario=$scenario \
workload=web-1k $(level_meta $scenario web-1k $level)"
                reset_lb
                read_counters_begin
                read_cpu_begin
                run_traffic split_direct $scenario $split ${level#*:}
                read_cpu_end
                read_counters_end
            done
        done
    done

    normal_duration=$HTTP_DURATION
    HTTP_DURATION=$DYNAMIC_DURATION
    for level in $(levels 1-1-0.5 web-1k "$TEST4_LEVELS"); do
        on_c quota ${QUOTA[1-1-1]} >/dev/null
        begin_round $TEST-dynamic-equal-web-1k-${level%:*} "test=$TEST baseline=equal scenario=dynamic \
workload=web-1k $(level_meta 1-1-0.5 web-1k $level)"
        reset_lb
        read_counters_begin
        read_cpu_begin
        run_traffic dynamic direct3 web-1k ${level#*:}
        read_cpu_end
        read_counters_end
    done
    HTTP_DURATION=$normal_duration

    for quota in $SINGLE_QUOTAS; do
        on_c quota "$quota% $quota% $quota%" >/dev/null
        begin_round $TEST-single-$quota "test=$TEST baseline=single quota_pct=$quota workload=web-1k level=sat $(http_meta)"
        reset_lb
        read_counters_begin
        read_cpu_begin
        run_traffic single
        read_cpu_end
        read_counters_end
    done
done

restore
write_result
