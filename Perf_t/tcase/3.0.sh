#!/bin/bash
REPS=10
DURATION=20
IDLE_DURATION=10
PPS_LIST="500000 100000"
source "$(dirname "$0")/run_lib.sh"

start_test 3.0 "$@"

B_OFF_PATH=1
on_c mode guarded
on_c quota ${QUOTA[equal]} >/dev/null
on_c mode direct

for rep in $(seq $REPS); do
    run_idle_round $TEST-none "test=$TEST variant=none"

    for profile in est new; do
        for pps in $PPS_LIST; do
            begin_round $TEST-none-$profile-$pps "test=$TEST variant=none size=64 pps=$pps \
$(flow_meta $profile $(ports_of $profile) 3)"
            reset_lb
            read_counters_begin
            read_cpu_begin
            run_traffic pktgen size=64 pps=$pps seconds=$DURATION ports=$(ports_of $profile) dst_mac=$SERVER_MAC \
                dsts="$(backend_ip 1) $(backend_ip 2) $(backend_ip 3)"
            read_cpu_end
            read_counters_end
        done
    done
done

restore
write_result
