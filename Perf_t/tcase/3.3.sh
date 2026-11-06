#!/bin/bash
REPS=10
DURATION=60
IDLE_DURATION=60
REST=10
DPS_LIST="20000 40000 60000 80000 100000 120000 140000 160000 180000 200000"
source "$(dirname "$0")/run_lib.sh"

start_test 3.3 "$@"
prepare_one_core
on_c mode guarded
on_c quota ${QUOTA[equal]} >/dev/null
on_b mode xdp >/dev/null
make_frag_packet_file 2 >/dev/null

for rep in $(seq $REPS); do
    for fragment in off on; do
        on_b feature fragment $fragment
        run_idle_one_core $TEST-$fragment "test=$TEST variant=xdp fragment=$fragment lb_cores=1"

        for dps in $DPS_LIST; do
            begin_round $TEST-$fragment-$dps "test=$TEST variant=xdp fragment=$fragment lb_cores=1 frags=2 \
dps=$dps pps=$(( dps * 2 )) profile=est flows=1000 duration=$DURATION"
            reset_lb_one_core
            read_counters_begin
            read_cpu_begin
            read_core0_begin
            run_traffic frag 2 $(( dps * 2 )) $DURATION
            read_core0_end
            read_cpu_end
            read_counters_end
            sleep $REST
        done
    done
done

restore
write_result
