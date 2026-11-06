#!/bin/bash
REPS=5
DURATION=60
IDLE_DURATION=60
REST=10
LB_LIST="xdp ipvs nft ipt nginx"
UDP_POINTS="64:50000 64:100000 64:250000 64:500000 64:1000000
            128:50000 128:100000 128:250000 128:500000
            512:50000 512:100000
            1024:50000 1024:100000"
source "$(dirname "$0")/run_lib.sh"

read_cycles() {
    curl -s -m 3 http://$LB_IP:9100/metrics | awk -v t=$(date +%s%N) '
        /^node_perf_cpucycles_total/ { c += $2 }
        /^node_cpu_scaling_frequency_hertz/ { f += $2; n++ }
        END { printf "time_ns=%s\ncycles=%.0f\nfreq_hz=%.0f\n", t, c, n ? f / n : 0 }' > "$out.p$1"
}

start_test 1.5 "$@"
curl -s -m 3 http://$LB_IP:9100/metrics | grep -q '^node_perf_cpucycles_total' ||
    { echo "ไม่มี node_exporter (perf) บน B  สั่ง /opt/monitor/monitor.sh start บน A ก่อน"; exit 1; }

for rep in $(seq $REPS); do
    for mode in $(select_lb $LB_LIST); do
        switch_lb $mode

        begin_round $TEST-$mode-idle "kind=idle test=$TEST mode=$mode"
        reset_lb
        read_counters_begin
        read_cycles 0
        read_cpu_begin
        run_traffic sleep $IDLE_DURATION
        read_cpu_end
        read_cycles 1
        read_counters_end

        for point in $UDP_POINTS; do
            size=${point%:*} pps=${point#*:}
            begin_round $TEST-$mode-$size-$pps "test=$TEST mode=$mode size=$size pps=$pps \
link_bound=$(( pps * (size + 40) * 8 >= 950000000 )) $(flow_meta est $EST_PORTS)"
            reset_lb
            read_counters_begin
            read_cycles 0
            read_cpu_begin
            run_traffic pktgen dst_mac=$LB_MAC dst=$VIP size=$size pps=$pps seconds=$DURATION
            read_cpu_end
            read_cycles 1
            read_counters_end
            sleep $REST
        done
    done
done

restore
write_result
