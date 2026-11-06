#!/bin/bash
REPS=10
HTTP_DURATION=40
TEST4_LEVELS="50 60 70 80"
VARIANTS="xdp:ecmp xdp:wcmp xdp:awfd4s ipvs:rr ipvs:wlc nft:rr ipt:rr nginx:least_conn haproxy:leastconn"
SCENARIO=1-1-1
source "$(dirname "$0")/run_lib.sh"

start_test 4.1 "$@"
check_test4 $SCENARIO

for rep in $(seq $REPS); do
    for variant in $(select_lb $VARIANTS); do
        switch_lb ${variant%%:*}
        RESET_ARGS="algo $(variant_algo $variant $SCENARIO)"

        for level in $(test4_levels $SCENARIO $variant); do
            on_c quota ${QUOTA[$SCENARIO]} >/dev/null
            begin_round $TEST-${variant/:/-}-web-1k-${level%:*} "test=$TEST mode=${variant%%:*} algo=${variant#*:} \
scenario=$SCENARIO workload=web-1k $(level_meta $SCENARIO web-1k $level)"
            reset_lb
            read_counters_begin
            read_cpu_begin
            run_traffic via_vip web-1k ${level#*:}
            read_cpu_end
            read_counters_end
        done
    done
done

restore
write_result
