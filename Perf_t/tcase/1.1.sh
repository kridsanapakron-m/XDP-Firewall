#!/bin/bash
# ข้อ 1.1  UDP: CPU ของ B ต่อ packet
#
# เป้าหมาย  CPU ของ B ต่อ packet ที่ส่งต่อสำเร็จ และ pps สูงสุดที่ loss_lb ≤ 0.1% ที่ pps/ขนาดเดียวกัน
# factor    mode = xdp ipvs nft ipt nginx (haproxy ไม่รองรับ UDP)
#           64 B × 50k 100k 250k 500k 1M pps  และ  512 1024 1400 B × 50k pps
# คงที่     UDP ไป VIP:8080 flow EST 1,000 tuple, pktgen 2 thread, 20 s, 10 rep, รอบ idle 10 s ต่อ mode, bpf_stats ปิด
# ผล        results/<ชุด>/<ข้อ>/<id>-r<rep>.{meta,client,a0,a1,b0,b1,c0,c1,cpu-{a,b,c}.json.gz}  และ report.txt
# รัน       sudo ./tcase/1.1.sh  |  ./tcase/1.1.sh plan  |  ./tcase/1.1.sh report [dir]
#           ปรับค่าผ่าน env เช่น REPS=1 DURATION=5 RUN_DIR=results/x sudo -E ./tcase/1.1.sh  (RESUME=1 ข้ามรอบที่เสร็จแล้ว)
#
# ===== การตั้งเครื่องของข้อนี้ =====
# สคริปต์ตั้งให้เองผ่าน setup_b_lb.sh / setup_c_server.sh  ข้างล่างคือคำสั่งที่ให้ผลเท่ากัน ใช้ทำมือได้
# ตั้งเครื่องครั้งแรก: ดูหัวไฟล์ tcase/run_lib.sh
# ดึงบล็อกออกมาเป็นคำสั่งพร้อมวาง (ลบ "#   " นำหน้า) เช่น  sed -n '/^# --- C: quota/,/^#$/s/^#   //p' tcase/1.1.sh
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
# --- B: mode ipvs  (B$ setup_b_lb.sh mode ipvs)  IPVS round robin แบบ tunnel (IPIP) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   modprobe ip_vs; modprobe ipip
#   for svc in "-t $VIP:$VPORT" "-u $VIP:$VPORT" "-t $VIP:$IPERF_PORT"; do
#       ipvsadm -A $svc -s rr
#       for i in 1 2 3; do ipvsadm -a $svc -r $(backend_ip $i) -i; done
#   done
#
# --- B: mode nft  (B$ setup_b_lb.sh mode nft)  nftables DNAT แบบ round robin (numgen) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   sysctl -w net.netfilter.nf_conntrack_max=1048576
#   b="0 : $(backend_ip 1), 1 : $(backend_ip 2), 2 : $(backend_ip 3)"
#   nft -f - <<EOF
#   table ip perf_lb {
#   chain prerouting { type nat hook prerouting priority dstnat;
#   ip daddr $VIP tcp dport { $VPORT, $IPERF_PORT } dnat to numgen inc mod 3 map {
#   $b }
#   ip daddr $VIP udp dport $VPORT dnat to numgen inc mod 3 map {
#   $b }
#   }
#   }
#   EOF
#
# --- B: mode ipt  (B$ setup_b_lb.sh mode ipt)  iptables-legacy DNAT แบ่ง 3 ส่วนด้วย statistic nth ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   sysctl -w net.netfilter.nf_conntrack_max=1048576
#   iptables-legacy -t nat -N PERF_LB
#   iptables-legacy -t nat -A PREROUTING -j PERF_LB
#   for m in "-p tcp -m multiport --dports $VPORT,$IPERF_PORT" "-p udp --dport $VPORT"; do
#       iptables-legacy -t nat -A PERF_LB -d $VIP $m -m statistic --mode nth --every 3 --packet 0 -j DNAT --to-destination $(backend_ip 1)
#       iptables-legacy -t nat -A PERF_LB -d $VIP $m -m statistic --mode nth --every 2 --packet 0 -j DNAT --to-destination $(backend_ip 2)
#       iptables-legacy -t nat -A PERF_LB -d $VIP $m -j DNAT --to-destination $(backend_ip 3)
#   done
#
# --- B: mode nginx  (B$ setup_b_lb.sh mode nginx)  nginx stream proxy TCP + UDP ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   m=/usr/lib/nginx/modules/ngx_stream_module.so
#   cat > /etc/nginx/perf-lb.conf <<EOF
#   $([ -f $m ] && echo "load_module $m;")
#   worker_processes auto; worker_rlimit_nofile 65536; pid /run/perf-lb-nginx.pid; error_log /var/log/perf-lb-nginx.err warn;
#   events { worker_connections 16384; }
#   stream {
#   upstream tcp_backends { server $(backend_ip 1):$VPORT; server $(backend_ip 2):$VPORT; server $(backend_ip 3):$VPORT; }
#   upstream udp_backends { server $(backend_ip 1):$VPORT; server $(backend_ip 2):$VPORT; server $(backend_ip 3):$VPORT; }
#   upstream iperf_backends { server $(backend_ip 1):$IPERF_PORT; server $(backend_ip 2):$IPERF_PORT; server $(backend_ip 3):$IPERF_PORT; }
#   server { listen $VIP:$VPORT reuseport; proxy_pass tcp_backends; }
#   server { listen $VIP:$IPERF_PORT reuseport; proxy_pass iperf_backends; }
#   server { listen $VIP:$VPORT udp reuseport; proxy_pass udp_backends; proxy_responses 0; }
#   }
#   EOF
#   nginx -c /etc/nginx/perf-lb.conf < /dev/null >> /var/log/perf-lb-nginx.err 2>&1
#
# --- B: mode haproxy  (B$ setup_b_lb.sh mode haproxy)  HAProxy TCP roundrobin (ไม่รองรับ UDP) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   mkdir -p /etc/haproxy
#   cat > /etc/haproxy/perf-lb.cfg <<EOF
#   global
#       daemon
#       maxconn 200000
#       pidfile /run/perf-lb-haproxy.pid
#   defaults
#       mode tcp
#       timeout connect 5s
#       timeout client 60s
#       timeout server 60s
#   frontend vip
#       bind $VIP:$VPORT,$VIP:$IPERF_PORT
#       default_backend web
#   backend web
#       balance roundrobin
#       server b1 $(backend_ip 1)
#       server b2 $(backend_ip 2)
#       server b3 $(backend_ip 3)
#   EOF
#   haproxy -f /etc/haproxy/perf-lb.cfg < /dev/null >> /var/log/perf-lb-haproxy.log 2>&1
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
# --- C: mode nat  (C$ setup_c_server.sh mode nat)  nft/ipt DNAT: ขากลับไป A ต้องผ่าน B เพื่อแปลง address กลับ ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   nft delete table inet perf_guard
#   nft -f - <<EOF
#   table inet perf_guard {
#   chain forward {
#   type filter hook forward priority 0; policy accept;
#   }
#   }
#   EOF
#   ip route replace $CLIENT_IP/32 via $LB_IP dev $SERVER_IFACE
#
# --- C: quota ของ backend 1 2 3 = 100% 100% 100%  (C$ setup_c_server.sh quota 100% 100% 100%) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   q=(100% 100% 100%)
#   for i in 1 2 3; do systemctl set-property --runtime backend$i.scope CPUQuota=${q[i-1]} CPUQuotaPeriodSec=10ms; done
#
# --- A: ยิงหนึ่งรอบด้วย pktgen  (ตัวอย่าง 64 B 100k pps 20 s flow EST) ---
#   source <repo บน A>/Perf_t/perf_env.sh
#   SIZE=64 PPS=100000 SEC=20 PORTS=4 DST=$VIP DST_COUNT=1 MAC=$(mac_of $LB_IP)
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

# จุดยิง: 64 B × PPS_LADDER (+ STRESS_PPS) แล้ว SIZES × SIZE_SWEEP_PPS  (จุดซ้ำนับครั้งเดียว)
udp_points() {
    local pps size
    for pps in $PPS_LADDER $STRESS_PPS; do echo 64:$pps; done
    for size in $SIZES; do echo $size:$SIZE_SWEEP_PPS; done
}

# packet ที่ B ส่งต่อ: xdp = xdp_redirect ของ xdp_lb_ctl stats (XDP_REDIRECT ไม่นับใน tx_packets), mode อื่น = tx_packets ของ NIC
forwarded() {
    if [ $1 = xdp ]; then cmd b "$B_STATS" | field xdp_redirect; else cmd b "$B_NIC/tx_packets"; fi
}

# หนึ่งรอบ: UDP <size> B ที่ <pps> ไป VIP
one_round() {
    local mode=$1 size=$2 pps=$3 rx0 rx1 miss0 miss1 fwd0 fwd1 udp0 udp1
    round_begin $TEST-$mode-$size-$pps $DURATION "test=$TEST mode=$mode size=$size pps=$pps \
link_bound=$(( pps * (size + 40) * 8 >= 950000000 )) $(flow_meta est $EST_PORTS)" || return 0
    # ขั้นที่ 1  รีเซ็ต B: โหลด mode เดิมใหม่ให้ map ว่าง + conntrack -F แล้วรอ SETTLE
    reset_b
    # ขั้นที่ 2  อ่านค่าก่อนยิง: packet ที่ NIC ของ B รับ / ตกหล่น, packet ที่ B ส่งต่อ, UDP ที่ backend ทั้ง 3 ตัวรับ
    rx0=$(cmd b "$B_NIC/rx_packets")
    miss0=$(cmd b "$B_NIC/rx_missed_errors")
    fwd0=$(forwarded $mode)
    udp0=$(cmd c "$C_UDP_IN")
    # ขั้นที่ 3  เก็บตัวนับก่อนยิงของ A B C (.a0 .b0 .c0) แล้วเริ่ม mpstat บน A B C
    read_counters 0
    cpu_begin
    # ขั้นที่ 4  ยิง: pktgen 2 thread  <size> B  <pps> pps  20 s  ไป VIP:8080
    traffic pktgen dst_mac=$LB_MAC dst=$VIP size=$size pps=$pps seconds=$DURATION
    # ขั้นที่ 5  หยุด mpstat  เก็บตัวนับหลังยิง (.a1 .b1 .c1)  ตรวจว่ายิงได้ ≥ 95% ของเป้า
    cpu_end
    read_counters 1
    round_end
    # ขั้นที่ 6  อ่านค่าหลังยิงแล้วแสดง ก่อน → หลัง และ CPU ของ B (เทียบรอบ idle ของ mode นี้)
    rx1=$(cmd b "$B_NIC/rx_packets")
    miss1=$(cmd b "$B_NIC/rx_missed_errors")
    fwd1=$(forwarded $mode)
    udp1=$(cmd c "$C_UDP_IN")
    delta "B rx_packets" "$rx0" "$rx1"
    delta "B rx_missed_errors" "$miss0" "$miss1"
    delta "B ส่งต่อ" "$fwd0" "$fwd1"
    delta "C udp_in (3 backend)" "$udp0" "$udp1"
    show_cpu b
}

t1_1() {
    local mode point
    for rep in $(seq $REPS_UDP); do
        for mode in $TEST1_MODES; do
            if [ $mode = haproxy ]; then continue; fi       # haproxy ไม่รองรับ UDP
            # เตรียม: B$ setup_b_lb.sh mode <mode>   C$ setup_c_server.sh mode guarded (nft ipt = nat)
            use_mode $mode
            # รอบ idle 10 s: CPU ตอนไม่มี traffic ของ mode นี้ ไว้หักออก
            idle_round $TEST-$mode "test=$TEST mode=$mode"
            for point in $(udp_points | awk '!seen[$0]++'); do one_round $mode ${point%:*} ${point#*:}; done
        done
    done
    restore                                             # คืน B = xdp, C = guarded
}

run_one 1.1 "$@"
