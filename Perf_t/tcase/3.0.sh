#!/bin/bash
# ข้อ 3.0  ไม่มี LB (ยิงตรงไป C)
#
# เป้าหมาย  จุดอ้างอิงไม่มี LB: pktgen thread ละ backend ยิงตรงไป C (ดูว่า C รับได้แค่ไหน)
# factor    flow = EST, NEW  ×  pps = 500k, 100k
# คงที่     UDP 64 B, pktgen 3 thread (thread ละ backend), 20 s, 10 rep, รอบ idle 10 s
# ผล        results/<ชุด>/<ข้อ>/<id>-r<rep>.{meta,client,a0,a1,b0,b1,c0,c1,cpu-{a,b,c}.json.gz}  และ report.txt
# รัน       sudo ./tcase/3.0.sh  |  ./tcase/3.0.sh plan  |  ./tcase/3.0.sh report [dir]
#           ปรับค่าผ่าน env เช่น REPS=1 DURATION=5 RUN_DIR=results/x sudo -E ./tcase/3.0.sh  (RESUME=1 ข้ามรอบที่เสร็จแล้ว)
#
# ===== การตั้งเครื่องของข้อนี้ =====
# สคริปต์ตั้งให้เองผ่าน setup_b_lb.sh / setup_c_server.sh  ข้างล่างคือคำสั่งที่ให้ผลเท่ากัน ใช้ทำมือได้
# ตั้งเครื่องครั้งแรก: ดูหัวไฟล์ tcase/run_lib.sh
# ดึงบล็อกออกมาเป็นคำสั่งพร้อมวาง (ลบ "#   " นำหน้า) เช่น  sed -n '/^# --- C: quota/,/^#$/s/^#   //p' tcase/3.0.sh
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
# --- B: ไม่แตะ  B ไม่อยู่ในเส้นทาง (A ยิงตรงไป C)  ไม่สลับ XDP การ์ดของ B จึงไม่ reset ---
#   # ไม่มีคำสั่ง
#
# --- B: ตัวนับเวลาของ BPF  (B$ setup_b_lb.sh bpf-stats on|off)  ให้ bpftool รายงาน run_cnt และ run_time_ns ---
#   sysctl -w kernel.bpf_stats_enabled=1           # เปิดตอนเริ่มข้อ
#   sysctl -w kernel.bpf_stats_enabled=0           # ปิดตอนจบข้อ
#
# --- C: mode direct  (C$ setup_c_server.sh mode direct)  A ยิงตรงไป backend ได้ (ไม่มี LB) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   nft delete table inet perf_guard
#   nft -f - <<EOF
#   table inet perf_guard {
#   chain forward {
#   type filter hook forward priority 0; policy accept;
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
# --- A: ยิงหนึ่งรอบด้วย pktgen 3 thread  (ตัวอย่าง flow EST 500k pps 20 s  thread t ยิงไป backend t+1) ---
#   source <repo บน A>/Perf_t/perf_env.sh
#   SIZE=64 PPS=500000 SEC=20 PORTS=4 MAC=$(mac_of $SERVER_IP)
#   modprobe pktgen
#   for d in /proc/net/pktgen/kpktgend_*; do echo rem_device_all > $d; done
#   for t in 0 1 2; do
#       src=$(ip_add $FLOW_SRC_BASE $((t * 125))) dst=$(backend_ip $((t + 1)))
#       echo "add_device $CLIENT_IFACE@$t" > /proc/net/pktgen/kpktgend_$t
#       for c in "count $((PPS * SEC / 3))" "clone_skb 0" "pkt_size $((SIZE - 4))" "ratep $((PPS / 3))" \
#                "dst_mac $MAC" "dst_min $dst" "dst_max $dst" "src_min $src" "src_max $(ip_add $src 124)" \
#                "udp_dst_min $VPORT" "udp_dst_max $VPORT" "udp_src_min 1024" "udp_src_max $((1024 + PORTS))" \
#                "queue_map_min $t" "queue_map_max $t"; do
#           echo "$c" > /proc/net/pktgen/$CLIENT_IFACE@$t
#       done
#   done
#   echo start > /proc/net/pktgen/pgctrl
#   grep -A1 '^Result:' /proc/net/pktgen/$CLIENT_IFACE@*
#
# ===== ขั้นตอน =====
# shellcheck disable=SC2086,SC2034   # แยกคำโดยตั้งใจ, rep ใช้ใน run_lib.sh
# shellcheck source=run_lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

# หนึ่งรอบ: flow <profile> ที่ <pps> ยิงตรงไป backend 3 ตัว
one_round() {
    local profile=$1 pps=$2 udp0 udp1 miss0 miss1
    shift 2
    round_begin $TEST-none-$profile-$pps $DURATION "test=$TEST variant=none size=64 pps=$pps \
$(flow_meta $profile $(ports_of $profile) ${threads:-})" || return 0
    # ขั้นที่ 1  B ไม่อยู่ในเส้นทาง ไม่แตะ B (B_OFF_PATH) แล้วรอ SETTLE
    reset_b
    # ขั้นที่ 2  อ่านค่าก่อนยิง: UDP ที่ backend ทั้ง 3 ตัวรับ และ packet ที่ NIC ของ C ตกหล่น
    udp0=$(cmd c "$C_UDP_IN")
    miss0=$(cmd c "$C_NIC/rx_missed_errors")
    # ขั้นที่ 3  เก็บตัวนับก่อนยิง แล้วเริ่ม mpstat
    read_counters 0
    cpu_begin
    # ขั้นที่ 4  ยิง: pktgen 3 thread ไป backend 1 2 3 (MAC ของ C) 64 B <pps> 20 s
    traffic pktgen size=64 pps=$pps seconds=$DURATION ports=$(ports_of $profile) "$@"
    # ขั้นที่ 5  หยุด mpstat  เก็บตัวนับหลังยิง  ตรวจ rate
    cpu_end
    read_counters 1
    round_end
    # ขั้นที่ 6  อ่านค่าหลังยิงแล้วแสดง
    udp1=$(cmd c "$C_UDP_IN")
    miss1=$(cmd c "$C_NIC/rx_missed_errors")
    delta "C udp_in (3 backend)" "$udp0" "$udp1"
    delta "C rx_missed_errors" "$miss0" "$miss1"
    show_cpu c
}

t3_0() {
    local threads=3 profile pps B_OFF_PATH=1
    # เตรียม: C$ setup_c_server.sh mode guarded + quota 100% แล้ว mode direct  B ไม่อยู่ในเส้นทาง ไม่แตะ
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
