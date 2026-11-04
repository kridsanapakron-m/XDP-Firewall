#!/bin/bash
DURATION=${DURATION:-60}
IDLE_DURATION=${IDLE_DURATION:-60}
REPS_UDP=${REPS_UDP:-${REPS:-5}}
TEST1_MODES=${TEST1_MODES:-"xdp ipvs nft ipt nginx"}
UDP_POINTS=${UDP_POINTS:-"64:50000 64:100000 64:250000 64:500000 64:1000000 128:50000 128:100000 128:250000 128:500000
                          512:50000 512:100000 1024:50000 1024:100000"}
TEST15_REST=${TEST15_REST:-10}
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

perf_snap() {
    curl -s -m 3 http://$LB_IP:9100/metrics | awk -v t=$(date +%s%N) '
        /^node_perf_cpucycles_total/ { c += $2 }
        /^node_cpu_scaling_frequency_hertz/ { f += $2; n++ }
        END { printf "time_ns=%s\ncycles=%.0f\nfreq_hz=%.0f\n", t, c, n ? f / n : 0 }' > "$out.p$1"
}

idle_perf_round() {
    round_begin $TEST-$1-idle $IDLE_DURATION "kind=idle test=$TEST mode=$1" || return 0
    reset_b
    read_counters 0
    perf_snap 0
    cpu_begin
    traffic sleep $IDLE_DURATION
    cpu_end
    perf_snap 1
    read_counters 1
    round_end
}

one_round() {
    local mode=$1 size=$2 pps=$3 fwd0 fwd1
    round_begin $TEST-$mode-$size-$pps $(( DURATION + TEST15_REST )) "test=$TEST mode=$mode size=$size pps=$pps \
link_bound=$(( pps * (size + 40) * 8 >= 950000000 )) $(flow_meta est $EST_PORTS)" || return 0
    reset_b
    fwd0=$(forwarded $mode)
    read_counters 0
    perf_snap 0
    cpu_begin
    traffic pktgen dst_mac=$LB_MAC dst=$VIP size=$size pps=$pps seconds=$DURATION
    cpu_end
    perf_snap 1
    read_counters 1
    round_end
    fwd1=$(forwarded $mode)
    delta "B ส่งต่อ" "$fwd0" "$fwd1"
    sleep $TEST15_REST
}

t1_5() {
    local mode point
    [ -n "$PLAN" ] || curl -s -m 3 http://$LB_IP:9100/metrics | grep -q '^node_perf_cpucycles_total' ||
        { echo "ไม่มี node_exporter (perf) บน B  สั่ง /opt/monitor/monitor.sh start บน A ก่อน"; exit 1; }
    for rep in $(seq $REPS_UDP); do
        for mode in $TEST1_MODES; do
            if [ $mode = haproxy ]; then continue; fi
            use_mode $mode
            idle_perf_round $mode
            for point in $(printf '%s\n' $UDP_POINTS | awk '!seen[$0]++'); do one_round $mode ${point%:*} ${point#*:}; done
        done
    done
    restore
}

run_one 1.5 "$@"
