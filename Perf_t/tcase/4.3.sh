#!/bin/bash
# ข้อ 4.3  อัลกอริทึม oneslow
#
# เป้าหมาย  latency, error และ balance ของอัลกอริทึมที่ load เท่ากัน (% ของ C0) เมื่อ backend เป็นตัวจำกัด
# factor    variant (TEST4_VARIANTS) = xdp:ecmp xdp:wcmp xdp:awfd4 | ipvs:rr ipvs:wlc nft:rr ipt:rr nginx:least_conn
#           haproxy:leastconn (least-connection ใส่น้ำหนัก = quota)   load = 50 75 90% ของ C0 + sat (rep แรกเท่านั้น)
# คงที่     web-1k wrk2 128 connection, connection ใหม่ทุก 100 request, quota 40% 40% 10%, 40 s, 10 rep
# ผล        results/<ชุด>/<ข้อ>/<id>-r<rep>.{meta,client,a0,a1,b0,b1,c0,c1,cpu-{a,b,c}.json.gz}  และ report.txt
# รัน       sudo ./tcase/4.3.sh  |  ./tcase/4.3.sh plan  |  ./tcase/4.3.sh report [dir]
#           ปรับค่าผ่าน env เช่น REPS=1 DURATION=5 RUN_DIR=results/x sudo -E ./tcase/4.3.sh  (RESUME=1 ข้ามรอบที่เสร็จแล้ว)
# ต้องมีก่อน C0 ของ oneslow web-1k ใน RUN_DIR เดียวกัน (tcase/0.3.sh)
#
# ===== การตั้งเครื่องของข้อนี้ =====
# สคริปต์ตั้งให้เองผ่าน setup_b_lb.sh / setup_c_server.sh  ข้างล่างคือคำสั่งที่ให้ผลเท่ากัน ใช้ทำมือได้
# ตั้งเครื่องครั้งแรก: ดูหัวไฟล์ tcase/run_lib.sh
# ดึงบล็อกออกมาเป็นคำสั่งพร้อมวาง (ลบ "#   " นำหน้า) เช่น  sed -n '/^# --- C: quota/,/^#$/s/^#   //p' tcase/4.3.sh
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
# --- B: algo wcmp  (B$ setup_b_lb.sh reset algo wcmp 4) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   kill $(cat /run/perf-awfd.pid) 2>/dev/null
#   bpftool -j map dump pinned $MAPS/awfd_map | jq -r '.[].key | join(" ")' |
#       while read -r key; do bpftool map delete pinned $MAPS/awfd_map key $key; done
#   setsid taskset -c $DAEMON_CPU $REPO/xdp_lb_awfd --static -m 4 > /var/log/perf-awfd.log 2>&1 < /dev/null &
#   echo $! > /run/perf-awfd.pid
#
# --- B: algo lcf  (B$ setup_b_lb.sh reset algo lcf 500) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   kill $(cat /run/perf-awfd.pid) 2>/dev/null
#   bpftool -j map dump pinned $MAPS/awfd_map | jq -r '.[].key | join(" ")' |
#       while read -r key; do bpftool map delete pinned $MAPS/awfd_map key $key; done
#   setsid taskset -c $DAEMON_CPU $REPO/xdp_lb_awfd -m 1 -i 500 > /var/log/perf-awfd.log 2>&1 < /dev/null &
#   echo $! > /run/perf-awfd.pid
#
# --- B: algo awfd2 / awfd4  (B$ setup_b_lb.sh reset algo awfd <2|4> 500) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   kill $(cat /run/perf-awfd.pid) 2>/dev/null
#   bpftool -j map dump pinned $MAPS/awfd_map | jq -r '.[].key | join(" ")' |
#       while read -r key; do bpftool map delete pinned $MAPS/awfd_map key $key; done
#   setsid taskset -c $DAEMON_CPU $REPO/xdp_lb_awfd -m 2 -i 500       # awfd4: -m 4 -i 500 > /var/log/perf-awfd.log 2>&1 < /dev/null &
#   echo $! > /run/perf-awfd.pid
#
# --- B: algo ecmp  (B$ setup_b_lb.sh reset algo ecmp) ---
#   # ไม่มี daemon (ใช้ hash ของ xdp_lb อย่างเดียว)
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
# --- C: quota ของ backend 1 2 3 = 40% 40% 10%  (C$ setup_c_server.sh quota 40% 40% 10%) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   q=(40% 40% 10%)
#   for i in 1 2 3; do systemctl set-property --runtime backend$i.scope CPUQuota=${q[i-1]} CPUQuotaPeriodSec=10ms; done
#
# --- A: ยิงหนึ่งรอบด้วย wrk2  (rate = C0(oneslow) × level ÷ 100 จาก c0.tsv) ---
#   source <repo บน A>/Perf_t/perf_env.sh
#   wrk2 -t 4 -c 128 -d 40s -R <rate> --latency http://$VIP:$VPORT/f1k     # sat ใช้ -R 2000000
#
# ===== ขั้นตอน =====
# shellcheck disable=SC2086,SC2034   # แยกคำโดยตั้งใจ, rep ใช้ใน run_lib.sh
# shellcheck source=run_lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

# หนึ่งรอบ: web-1k ที่ <level> ด้วย <algo>  (reset พร้อม algo = โหลด xdp ใหม่ให้ conn_map ว่าง แล้วเริ่ม daemon ครั้งเดียว)
one_round() {
    local variant=$1 level=$2 RESET_ARGS="algo $(variant_algo $1 oneslow)" r0 r1 i
    # เตรียม: quota 40% 40% 10%
    on_c quota ${QUOTA[oneslow]} >/dev/null
    round_begin $TEST-${variant/:/-}-web-1k-${level%:*} $HTTP_DURATION "test=$TEST mode=${variant%%:*} algo=${variant#*:} scenario=oneslow workload=web-1k \
$(level_meta oneslow web-1k $level)" || return 0
    # ขั้นที่ 1  รีเซ็ต B: โหลด mode ใหม่ด้วย algo ของ variant นี้ (xdp: เริ่ม daemon ครั้งเดียว) แล้วรอ SETTLE
    reset_b
    # ขั้นที่ 2  อ่านค่าก่อนยิง: request ที่ backend แต่ละตัวตอบไปแล้ว
    r0=$(cmd c "$C_REQUESTS")
    # ขั้นที่ 3  เก็บตัวนับก่อนยิง แล้วเริ่ม mpstat
    read_counters 0
    cpu_begin
    # ขั้นที่ 4  ยิง: wrk2 128 connection 40 s ไป VIP:8080/f1k  (-R = req/s ของ level  sat = -R 2000000)
    traffic via_vip web-1k ${level#*:}
    # ขั้นที่ 5  หยุด mpstat  เก็บตัวนับหลังยิง  ตรวจ rate
    cpu_end
    read_counters 1
    round_end
    # ขั้นที่ 6  อ่านค่าหลังยิงแล้วแสดง: request ต่อ backend (สัดส่วนควรตาม quota)
    r1=$(cmd c "$C_REQUESTS")
    for i in 1 2 3; do delta "C backend $i requests" "$(field b$i <<< "$r0")" "$(field b$i <<< "$r1")"; done
}

t4_3() {
    local variant level
    need_c0 oneslow web-1k
    if [ -z "$PLAN" ] && [ "$(c0_field oneslow web-1k 4)" = 1 ]; then
        echo "C0 ของ oneslow ใช้สายเกิน 90% (link-bound)  ลด QUOTA ของข้อ 4 ก่อน"
        exit 1
    fi
    check_variants
    for rep in $(seq $REPS_HTTP); do
        for variant in $TEST4_VARIANTS; do
            use_mode ${variant%%:*}               # B: mode เดิม = เขียนทับ ไม่ reset การ์ด  C: nft ipt = nat
            for level in $(levels oneslow web-1k "$TEST4_LEVELS") \
                    $(if [ $rep -le $TEST4_SAT_REPS ]; then echo sat:sat; fi); do
                one_round $variant $level
            done
        done
    done
    restore
}

run_one 4.3 "$@"
