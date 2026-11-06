#!/bin/bash
REPS=10
HTTP_DURATION=60
IDLE_DURATION=10
LB_LIST="xdp ipvs nft ipt nginx haproxy"
LOAD_PCT=75
source "$(dirname "$0")/run_lib.sh"

start_test 1.2 "$@"
need_c0 equal web-1k web-1k-close

for rep in $(seq $REPS); do
    for mode in $(select_lb $LB_LIST); do
        switch_lb $mode
        run_idle_round $TEST-$mode "test=$TEST mode=$mode"

        for load in web-1k web-1k-close; do
            for level in $(levels equal $load $LOAD_PCT) sat:sat; do
                begin_round $TEST-$mode-$load-${level%:*} "test=$TEST mode=$mode workload=$load $(level_meta equal $load $level)"
                reset_lb
                read_counters_begin
                read_cpu_begin
                run_traffic via_vip $load ${level#*:}
                read_cpu_end
                read_counters_end
            done
        done
    done
done

restore
write_result
