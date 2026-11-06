#!/bin/bash
REPS=10
DURATION=60
IDLE_DURATION=60
REST=10
PPS=100000
FRAG_COUNTS="1 2 3 4 5 6 7 8 9 10"
source "$(dirname "$0")/run_lib.sh"

start_test 3.5 "$@"
prepare_perf
on_c mode guarded
on_c quota ${QUOTA[equal]} >/dev/null
on_b mode xdp >/dev/null
on_b feature fragment on
for frags in $FRAG_COUNTS; do make_frag_packet_file $frags >/dev/null; done

for rep in $(seq $REPS); do
    run_idle_perf $TEST-fragment "test=$TEST variant=xdp fragment=on"

    for frags in $FRAG_COUNTS; do
        begin_round $TEST-$frags "test=$TEST variant=xdp fragment=on frags=$frags \
pps=$PPS dps=$(( PPS / frags )) profile=est flows=1000 duration=$DURATION"
        reset_lb
        read_counters_begin
        read_cpu_begin
        read_perf_begin
        run_traffic frag $frags $PPS $DURATION
        read_perf_end
        read_cpu_end
        read_counters_end
        sleep $REST
    done
done

restore
write_result
