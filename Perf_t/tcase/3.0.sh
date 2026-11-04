#!/bin/bash
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

one_round() {
    local profile=$1 pps=$2 udp0 udp1 miss0 miss1
    shift 2
    round_begin $TEST-none-$profile-$pps $DURATION "test=$TEST variant=none size=64 pps=$pps \
$(flow_meta $profile $(ports_of $profile) ${threads:-})" || return 0
    reset_b
    udp0=$(cmd c "$C_UDP_IN")
    miss0=$(cmd c "$C_NIC/rx_missed_errors")
    read_counters 0
    cpu_begin
    traffic pktgen size=64 pps=$pps seconds=$DURATION ports=$(ports_of $profile) "$@"
    cpu_end
    read_counters 1
    round_end
    udp1=$(cmd c "$C_UDP_IN")
    miss1=$(cmd c "$C_NIC/rx_missed_errors")
    delta "C udp_in (3 backend)" "$udp0" "$udp1"
    delta "C rx_missed_errors" "$miss0" "$miss1"
    show_cpu c
}

t3_0() {
    local threads=3 profile pps B_OFF_PATH=1
    on_c mode guarded
    on_c quota ${QUOTA[equal]} >/dev/null
    on_c mode direct
    for rep in $(seq $REPS_TEST3); do
        idle_round $TEST-none "test=$TEST variant=none"
        for profile in est new; do
            for pps in $TEST3_PPS; do
                one_round $profile $pps dst_mac=$SERVER_MAC dsts="$(backend_ip 1) $(backend_ip 2) $(backend_ip 3)"
            done
        done
    done
    restore
}

run_one 3.0 "$@"
