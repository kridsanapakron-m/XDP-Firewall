#!/bin/bash
# ข้อ 3.4  PMTU (DF)
#
# เป้าหมาย  PMTU: UDP ตั้ง DF ขนาด IP 1490 B (ห่อ IPIP แล้วเกิน 1500) ต้องได้ ICMP frag-needed ทุก packet
# factor    ขนาด IP = 1470 B (อ้างอิง ไม่เกิน), 1490 B
# คงที่     hping3 50k packet/s 20 s ไป VIP:8080, pmtu เปิด, route ไป VIP บน A ปลด mtu lock ชั่วคราว, 10 rep
#           ไม่ตัดรอบด้วย invalid=rate: report แสดง x = สั่ง, y = ส่งจริง, z = ถึง backend (1470) / ICMP (1490)
# ผล        results/<ชุด>/<ข้อ>/<id>-r<rep>.{meta,client,a0,a1,b0,b1,c0,c1,cpu-{a,b,c}.json.gz}  และ report.txt
# รัน       sudo ./tcase/3.4.sh  |  ./tcase/3.4.sh plan  |  ./tcase/3.4.sh report [dir]
#           ปรับค่าผ่าน env เช่น REPS=1 DURATION=5 RUN_DIR=results/x sudo -E ./tcase/3.4.sh  (RESUME=1 ข้ามรอบที่เสร็จแล้ว)
#
# ===== การตั้งเครื่องของข้อนี้ =====
# สคริปต์ตั้งให้เองผ่าน setup_b_lb.sh / setup_c_server.sh  ข้างล่างคือคำสั่งที่ให้ผลเท่ากัน ใช้ทำมือได้
# ตั้งเครื่องครั้งแรก: ดูหัวไฟล์ tcase/run_lib.sh
# ดึงบล็อกออกมาเป็นคำสั่งพร้อมวาง (ลบ "#   " นำหน้า) เช่น  sed -n '/^# --- C: quota/,/^#$/s/^#   //p' tcase/3.4.sh
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
# --- B: เปิด ICMP frag-needed (PMTU)  (B$ setup_b_lb.sh feature pmtu on)  ตั้งกลับทุกครั้งที่ reset ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   $REPO/xdp_lb_ctl pmtu on
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
# --- A: ปลด mtu lock ก่อนข้อนี้ แล้วล็อกกลับเมื่อจบ ---
#   source <repo บน A>/Perf_t/perf_env.sh
#   ip route replace $VIP/32 dev $CLIENT_IFACE                     # ก่อน
#   ip route replace $VIP/32 dev $CLIENT_IFACE mtu lock $VIP_MTU   # หลัง
#
# --- A: ยิงหนึ่งรอบด้วย hping3 (ตั้ง DF) ---
#   source <repo บน A>/Perf_t/perf_env.sh
#   timeout -s INT -k 5 20 hping3 -q -i u20 --udp -p $VPORT -y -d 1462 $VIP    # IP 1490 B = payload 1490 − 28
#   # 1470 B ใช้ -d 1442
#
# ===== ขั้นตอน =====
# shellcheck disable=SC2086,SC2034   # แยกคำโดยตั้งใจ, rep ใช้ใน run_lib.sh
# shellcheck source=run_lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

# หนึ่งรอบ: UDP ตั้ง DF ขนาด IP <size>
one_round() {
    local size=$1 s0 s1 u0 u1
    round_begin $TEST-$size $DURATION "test=$TEST variant=pmtu ip_size=$size pps=$PMTU_PPS raw_tool=$RAW_TOOL \
duration=$DURATION" || return 0
    # ขั้นที่ 1  รีเซ็ต B (pmtu on) แล้วรอ SETTLE
    reset_b
    # ขั้นที่ 2  อ่านค่าก่อนยิง: ตัวนับ frag_needed / icmp_sent ของ xdp_lb และ UDP ที่ backend รับ
    s0=$(cmd b "$B_STATS")
    u0=$(cmd c "$C_UDP_IN")
    # ขั้นที่ 3  เก็บตัวนับก่อนยิง แล้วเริ่ม mpstat
    read_counters 0
    cpu_begin
    # ขั้นที่ 4  ยิง: hping3 -y (DF) ขนาด IP <size> 50k/s 20 s
    traffic raw df$size $PMTU_PPS $DURATION
    # ขั้นที่ 5  หยุด mpstat  เก็บตัวนับหลังยิง  ตรวจ rate
    cpu_end
    read_counters 1
    round_end
    # ขั้นที่ 6  อ่านค่าหลังยิงแล้วแสดง (1470: ถึง backend ทั้งหมด  1490: ICMP เท่ากับที่ส่ง)
    s1=$(cmd b "$B_STATS")
    u1=$(cmd c "$C_UDP_IN")
    delta "B frag_needed" "$(field frag_needed <<< "$s0")" "$(field frag_needed <<< "$s1")"
    delta "B icmp_sent" "$(field icmp_sent <<< "$s0")" "$(field icmp_sent <<< "$s1")"
    delta "C udp_in (3 backend)" "$u0" "$u1"
}

t3_4() {
    local size
    # เตรียม: C$ setup_c_server.sh mode guarded + quota 100%   B$ setup_b_lb.sh mode xdp + bpf-stats on
    on_c mode guarded
    on_c quota ${QUOTA[equal]} >/dev/null
    on_b mode xdp >/dev/null
    on_b bpf-stats on
    # เตรียม: B$ setup_b_lb.sh feature pmtu on   A$ ip route replace $VIP/32 dev $CLIENT_IFACE (ปลด mtu lock)
    on_b feature pmtu on
    vip_route
    for rep in $(seq $REPS_TEST3); do
        idle_round $TEST-pmtu "test=$TEST variant=pmtu"
        for size in 1470 1490; do one_round $size; done
    done
    vip_route mtu lock $VIP_MTU
    on_b bpf-stats off
    restore
}

run_one 3.4 "$@"
