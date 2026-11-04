#!/bin/bash
DURATION=${DURATION:-60}
IDLE_DURATION=${IDLE_DURATION:-60}
REPS_TEST3=${REPS_TEST3:-${REPS:-10}}
TEST33_DPS=${TEST33_DPS:-"20000 40000 60000 80000 100000 120000 140000 160000 180000 200000"}
TEST3_REST=${TEST3_REST:-10}
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

one_round() {
    local fragment=$1 dps=$2 f0 f1
    round_begin $TEST-$fragment-$dps $(( DURATION + TEST3_REST )) "test=$TEST variant=xdp fragment=$fragment lb_cores=1 frags=2 \
dps=$dps pps=$(( dps * 2 )) profile=est flows=1000 duration=$DURATION" || return 0
    reset_one_core
    f0=$(cmd c "$C_UDP_FRAG_IN")
    read_counters 0
    cpu_begin
    core0_begin
    traffic frag 2 $(( dps * 2 )) $DURATION
    core0_end
    cpu_end
    read_counters 1
    round_end
    f1=$(cmd c "$C_UDP_FRAG_IN")
    delta "C udp_frag_in (ประกอบได้)" "$f0" "$f1"
    echo "  ส่งถึง backend                  $(( (f1 - f0) * 100 / $(sent_of) ))% ของ $(sent_of) datagram"
    per_unit0 datagram $(sent_of)
    sleep $TEST3_REST
}

t3_3() {
    local fragment dps
    one_core_start
    on_c mode guarded
    on_c quota ${QUOTA[equal]} >/dev/null
    on_b mode xdp >/dev/null
    if [ -z "$PLAN" ]; then frag_pcap 2 >/dev/null; fi
    for rep in $(seq $REPS_TEST3); do
        for fragment in off on; do
            on_b feature fragment $fragment
            idle_one_core $TEST-$fragment "test=$TEST variant=xdp fragment=$fragment lb_cores=1"
            for dps in $TEST33_DPS; do one_round $fragment $dps; done
        done
    done
    restore
}

run_one 3.3 "$@"
