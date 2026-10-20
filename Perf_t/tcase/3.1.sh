#!/bin/bash
# ข้อ 3.1  xdp-hash / xdp / xdp + daemon
#
# เป้าหมาย  ต้นทุนต่อ packet ทีละขั้นของ xdp_lb: stateless hash → + conn_map → + daemon AWFD
# factor    variant = xdp-hash, xdp (ecmp + conn_map), xdp-awfd (m=4 interval 500 ms)  ×  flow EST, NEW  ×  500k, 100k pps
# คงที่     UDP 64 B ไป VIP:8080, 20 s, 10 rep, รอบ idle 10 s ต่อ variant, bpf_stats เปิด (มี overhead เทียบข้อ 1 ตรง ๆ ไม่ได้)
# ผล        results/<ชุด>/<ข้อ>/<id>-r<rep>.{meta,client,a0,a1,b0,b1,c0,c1,cpu-{a,b,c}.json.gz}  และ report.txt
# รัน       sudo ./tcase/3.1.sh  |  ./tcase/3.1.sh plan  |  ./tcase/3.1.sh report [dir]
#           ปรับค่าผ่าน env เช่น REPS=1 DURATION=5 RUN_DIR=results/x sudo -E ./tcase/3.1.sh  (RESUME=1 ข้ามรอบที่เสร็จแล้ว)
#
# ===== การตั้งเครื่องของข้อนี้ =====
# สคริปต์ตั้งให้เองผ่าน setup_b_lb.sh / setup_c_server.sh  ข้างล่างคือคำสั่งที่ให้ผลเท่ากัน ใช้ทำมือได้
# ตั้งเครื่องครั้งแรก: ดูหัวไฟล์ tcase/run_lib.sh
# ดึงบล็อกออกมาเป็นคำสั่งพร้อมวาง (ลบ "#   " นำหน้า) เช่น  sed -n '/^# --- C: quota/,/^#$/s/^#   //p' tcase/3.1.sh
#
# --- B: ถอด mode เดิม (setup_b_lb.sh ทำก่อนตั้ง mode ใหม่ทุกครั้ง รวมถึงตอน reset) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   kill $(cat /run/perf-awfd.pid) 2>/dev/null; rm -f /run/perf-awfd.pid      # daemon ของ AWFD
#   # ถอด XDP เฉพาะเมื่อเปลี่ยนไป mode ที่ไม่ใช่ xdp: ถอด/ใส่ XDP ทำให้ ixgbe ของ B reset และ link หลุดชั่วครู่
#   # (xdp -> xdp ไม่ถอด ใช้ bpftool net attach ... overwrite ทับแทน)
#   bpftool net detach xdpdrv dev $LB_IFACE; bpftool net detach xdpgeneric dev $LB_IFACE
#   rm -rf $PIN
#   ipvsadm -C; modprobe -r ip_vs_rr ip_vs
#   nft delete table ip perf_lb
#   iptables-legacy -t nat -D PREROUTING -j PERF_LB; iptables-legacy -t nat -F PERF_LB; iptables-legacy -t nat -X PERF_LB
#   modprobe -r iptable_nat
#   kill $(cat /run/perf-lb-nginx.pid /run/perf-lb-haproxy.pid 2>/dev/null) 2>/dev/null
#   rm -f /run/perf-lb-nginx.pid /run/perf-lb-haproxy.pid
#
# --- B: ก่อนทุกรอบ  (B$ setup_b_lb.sh reset) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   ip -o addr show dev $LB_IFACE | grep -q " $VIP/32 " || ip addr add $VIP/32 dev $LB_IFACE
#   for i in 1 2 3; do ip route replace $(backend_ip $i)/32 via $SERVER_IP dev $LB_IFACE; done
#   # ถอด mode เดิมแล้วตั้งใหม่ตามบล็อกของ mode นั้น (map ว่าง) แล้วตั้ง feature / algo เดิมกลับ
#   conntrack -F
#
# --- B: ตัวนับเวลาของ BPF  (B$ setup_b_lb.sh bpf-stats on|off)  ให้ bpftool รายงาน run_cnt และ run_time_ns ---
#   sysctl -w kernel.bpf_stats_enabled=1           # เปิดตอนเริ่มข้อ
#   sysctl -w kernel.bpf_stats_enabled=0           # ปิดตอนจบข้อ
#
# --- B: mode xdp-hash  (B$ setup_b_lb.sh mode xdp-hash)  xdp_lb ที่ใช้ find_backend เดิม (stateless ไม่มี conn_map) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   sed 's/awfd(&flow, stats)/find_backend(\&flow)/' $REPO/xdp_lb.c > /tmp/xdp_lb_hash.c
#   clang -O2 -g -target bpf -I$REPO -I/usr/include/$(uname -m)-linux-gnu -c /tmp/xdp_lb_hash.c -o /tmp/xdp_lb_hash.o
#   mkdir -p $MAPS /etc/xdp_lb
#   bpftool prog load /tmp/xdp_lb_hash.o $PIN/prog type xdp pinmaps $MAPS
#   bpftool net attach xdpdrv pinned $PIN/prog dev $LB_IFACE overwrite
#   b="\"$(backend_ip 1)\", \"$(backend_ip 2)\", \"$(backend_ip 3)\""
#   cat > /etc/xdp_lb/xdp_lb.json <<EOF
#   {"fragment_handling": false, "icmp_pmtu": false, "services": [
#   {"vip": "$VIP", "port": $VPORT, "protocol": "tcp", "backends": [$b]}
#   ,{"vip": "$VIP", "port": $VPORT, "protocol": "udp", "backends": [$b]}
#   ,{"vip": "$VIP", "port": $VPORT_FRAG, "protocol": "udp", "backends": [$b]}
#   ,{"vip": "$VIP", "port": $IPERF_PORT, "protocol": "tcp", "backends": [$b]}
#   ]}
#   EOF
#   $REPO/xdp_lb_ctl apply                         # อ่าน /etc/xdp_lb/xdp_lb.json ลง vip_map และ backend_map
#   ping -c 1 -W 1 $SERVER_IP                      # bpf_fib_lookup ไม่ส่ง ARP เอง ต้องมี neighbor ของ C
#   # ค่าเริ่มต้นของ mode ใหม่: fragment off  pmtu off  algo ecmp (ไม่มี daemon)
#
# --- B: mode xdp  (B$ setup_b_lb.sh mode xdp)  VIP $VIP tcp/udp 8080, udp 8081, tcp 5001 -> backend 3 ตัว ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   mkdir -p $MAPS /etc/xdp_lb
#   bpftool prog load $REPO/xdp_lb.o $PIN/prog type xdp pinmaps $MAPS
#   bpftool net attach xdpdrv pinned $PIN/prog dev $LB_IFACE overwrite
#   b="\"$(backend_ip 1)\", \"$(backend_ip 2)\", \"$(backend_ip 3)\""
#   cat > /etc/xdp_lb/xdp_lb.json <<EOF
#   {"fragment_handling": false, "icmp_pmtu": false, "services": [
#   {"vip": "$VIP", "port": $VPORT, "protocol": "tcp", "backends": [$b]}
#   ,{"vip": "$VIP", "port": $VPORT, "protocol": "udp", "backends": [$b]}
#   ,{"vip": "$VIP", "port": $VPORT_FRAG, "protocol": "udp", "backends": [$b]}
#   ,{"vip": "$VIP", "port": $IPERF_PORT, "protocol": "tcp", "backends": [$b]}
#   ]}
#   EOF
#   $REPO/xdp_lb_ctl apply                         # อ่าน /etc/xdp_lb/xdp_lb.json ลง vip_map และ backend_map
#   ping -c 1 -W 1 $SERVER_IP                      # bpf_fib_lookup ไม่ส่ง ARP เอง ต้องมี neighbor ของ C
#   # ค่าเริ่มต้นของ mode ใหม่: fragment off  pmtu off  algo ecmp (ไม่มี daemon)
#
# --- B: variant xdp-awfd = mode xdp + daemon  (B$ setup_b_lb.sh reset algo awfd 4 500) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   kill $(cat /run/perf-awfd.pid) 2>/dev/null
#   bpftool -j map dump pinned $MAPS/awfd_map | jq -r '.[].key | join(" ")' |
#       while read -r key; do bpftool map delete pinned $MAPS/awfd_map key $key; done
#   setsid taskset -c $DAEMON_CPU $REPO/xdp_lb_awfd -m 4 -i 500 > /var/log/perf-awfd.log 2>&1 < /dev/null &
#   echo $! > /run/perf-awfd.pid
#
# --- C: mode guarded  (C$ setup_c_server.sh mode guarded)  กันไม่ให้ A ต่อตรงไป backend  ขากลับไป A โดยตรง (DSR) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   nft delete table inet perf_guard
#   nft -f - <<EOF
#   table inet perf_guard {
#   chain forward {
#   type filter hook forward priority 0; policy accept;
#   ip saddr $CLIENT_IP ip daddr 192.168.200.0/22 ct state new drop
#   }
#   }
#   EOF
#   ip route del $CLIENT_IP/32 via $LB_IP
#
# --- C: quota ของ backend 1 2 3 = 100% 100% 100%  (C$ setup_c_server.sh quota 100% 100% 100%) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   q=(100% 100% 100%)
#   for i in 1 2 3; do systemctl set-property --runtime backend$i.scope CPUQuota=${q[i-1]} CPUQuotaPeriodSec=10ms; done
#
# --- A: ยิงหนึ่งรอบด้วย pktgen  (ตัวอย่าง flow NEW 500k pps 20 s) ---
#   source <repo บน A>/Perf_t/perf_env.sh
#   SIZE=64 PPS=500000 SEC=20 PORTS=64511 DST=$VIP DST_COUNT=1 MAC=$(mac_of $LB_IP)
#   modprobe pktgen
#   for d in /proc/net/pktgen/kpktgend_*; do echo rem_device_all > $d; done
#   for t in 0 1; do
#       src=$(ip_add $FLOW_SRC_BASE $((t * 125)))
#       echo "add_device $CLIENT_IFACE@$t" > /proc/net/pktgen/kpktgend_$t
#       for c in "count $((PPS * SEC / 2))" "clone_skb 0" "pkt_size $((SIZE - 4))" "ratep $((PPS / 2))" \
#                "dst_mac $MAC" "dst_min $DST" "dst_max $(ip_add $DST $((DST_COUNT - 1)))" \
#                "src_min $src" "src_max $(ip_add $src 124)" "udp_dst_min $VPORT" "udp_dst_max $VPORT" \
#                "udp_src_min 1024" "udp_src_max $((1024 + PORTS))" "queue_map_min $t" "queue_map_max $t"; do
#           echo "$c" > /proc/net/pktgen/$CLIENT_IFACE@$t
#       done
#   done
#   echo start > /proc/net/pktgen/pgctrl                  # กลับมาเมื่อยิงครบ
#   grep -A1 '^Result:' /proc/net/pktgen/$CLIENT_IFACE@*  # จำนวนที่ยิงและ pps ที่ทำได้ต่อ thread
#   # pkt_size = ขนาด frame - 4 (FCS)  port ต้นทาง 1024 .. 1024+PORTS-1  (EST: PORTS=4, NEW: PORTS=64511)
#
# ===== ขั้นตอน =====
# shellcheck disable=SC2086,SC2034   # แยกคำโดยตั้งใจ, rep ใช้ใน run_lib.sh
# shellcheck source=run_lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

# หนึ่งรอบ: flow <profile> ที่ <pps>
one_round() {
    local variant=$VARIANT profile=$1 pps=$2 p0 p1 s0 s1
    shift 2
    round_begin $TEST-$variant-$profile-$pps $DURATION "test=$TEST variant=$variant size=64 pps=$pps \
$(flow_meta $profile $(ports_of $profile) ${threads:-})" || return 0
    # ขั้นที่ 1  รีเซ็ต B แล้วรอ SETTLE
    reset_b
    # ขั้นที่ 2  อ่านค่าก่อนยิง: run_cnt / run_time_ns ของ prog (bpf_stats) และตัวนับของ xdp_lb
    p0=$(cmd b "$B_PROG")
    s0=$(cmd b "$B_STATS")
    # ขั้นที่ 3  เก็บตัวนับก่อนยิง แล้วเริ่ม mpstat
    read_counters 0
    cpu_begin
    # ขั้นที่ 4  ยิง: pktgen 2 thread 64 B <pps> 20 s ไป VIP:8080 (EST = 1,000 tuple, NEW = ไม่ซ้ำ)
    traffic pktgen size=64 pps=$pps seconds=$DURATION ports=$(ports_of $profile) "$@"
    # ขั้นที่ 5  หยุด mpstat  เก็บตัวนับหลังยิง  ตรวจ rate
    cpu_end
    read_counters 1
    round_end
    # ขั้นที่ 6  อ่านค่าหลังยิงแล้วแสดง
    p1=$(cmd b "$B_PROG")
    s1=$(cmd b "$B_STATS")
    delta "B run_cnt" "$(field run_cnt <<< "$p0")" "$(field run_cnt <<< "$p1")"
    delta "B run_time_ns" "$(field run_time_ns <<< "$p0")" "$(field run_time_ns <<< "$p1")"
    ratio "ns ต่อ packet (xdp_ns)" "$(field run_time_ns <<< "$p0")" "$(field run_time_ns <<< "$p1")" \
        "$(field run_cnt <<< "$p0")" "$(field run_cnt <<< "$p1")"
    delta "B conn_new" "$(field conn_new <<< "$s0")" "$(field conn_new <<< "$s1")"
    delta "B conn_hit" "$(field conn_hit <<< "$s0")" "$(field conn_hit <<< "$s1")"
    delta "B awfd_dispatched" "$(field awfd_dispatched <<< "$s0")" "$(field awfd_dispatched <<< "$s1")"
}

# ทุก profile (EST, NEW) × TEST3_PPS ของ variant นี้
points() {
    local profile pps
    for profile in est new; do
        for pps in $TEST3_PPS; do one_round $profile $pps "$@"; done
    done
}

t3_1() {
    local VARIANT RESET_ARGS
    for rep in $(seq $REPS_TEST3); do
        for VARIANT in xdp-hash xdp xdp-awfd; do
            # เตรียม: C$ setup_c_server.sh mode guarded + quota 100%   B$ setup_b_lb.sh mode ${VARIANT%-awfd} + bpf-stats on
            on_c mode guarded
            on_c quota ${QUOTA[equal]} >/dev/null
            on_b mode ${VARIANT%-awfd} >/dev/null
            on_b bpf-stats on
            # xdp-awfd: reset ทุกรอบเริ่ม daemon xdp_lb_awfd -m 4 -i 500 (B$ setup_b_lb.sh reset algo awfd 4 500)
            RESET_ARGS=""
            if [ $VARIANT = xdp-awfd ]; then RESET_ARGS="algo awfd 4 500"; fi
            idle_round $TEST-$VARIANT "test=$TEST variant=$VARIANT"
            points dst_mac=$LB_MAC dst=$VIP
        done
    done
    on_b bpf-stats off
    restore
}

run_one 3.1 "$@"
