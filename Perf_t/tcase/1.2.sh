#!/bin/bash
# ข้อ 1.2  HTTP 1 KB: CPU ของ B ต่อ request
#
# เป้าหมาย  CPU ของ B ต่อ request ของ HTTP 1 KB ที่ load เท่ากัน และ LB ตัวไหนตันก่อน backend (sat)
# factor    mode = xdp ipvs nft ipt nginx haproxy   connection = keep-alive, close   load = 75% ของ C0, sat
# คงที่     web-1k, wrk2 4 thread 128 connection, 40 s, 10 rep, รอบ idle 10 s ต่อ mode
# ผล        results/<ชุด>/<ข้อ>/<id>-r<rep>.{meta,client,a0,a1,b0,b1,c0,c1,cpu-{a,b,c}.json.gz}  และ report.txt
# รัน       sudo ./tcase/1.2.sh  |  ./tcase/1.2.sh plan  |  ./tcase/1.2.sh report [dir]
#           ปรับค่าผ่าน env เช่น REPS=1 DURATION=5 RUN_DIR=results/x sudo -E ./tcase/1.2.sh  (RESUME=1 ข้ามรอบที่เสร็จแล้ว)
# ต้องมีก่อน C0 ของ equal web-1k และ web-1k-close ใน RUN_DIR เดียวกัน (tcase/0.1.sh)
#
# ===== การตั้งเครื่องของข้อนี้ =====
# สคริปต์ตั้งให้เองผ่าน setup_b_lb.sh / setup_c_server.sh  ข้างล่างคือคำสั่งที่ให้ผลเท่ากัน ใช้ทำมือได้
# ตั้งเครื่องครั้งแรก: ดูหัวไฟล์ tcase/run_lib.sh
# ดึงบล็อกออกมาเป็นคำสั่งพร้อมวาง (ลบ "#   " นำหน้า) เช่น  sed -n '/^# --- C: quota/,/^#$/s/^#   //p' tcase/1.2.sh
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
# --- A: ยิงหนึ่งรอบด้วย wrk2  (ตัวอย่าง web-1k 75% ของ C0 = 62784 req/s, 40 s) ---
#   source <repo บน A>/Perf_t/perf_env.sh
#   wrk2 -t 4 -c 128 -d 40s -R 62784 --latency http://$VIP:$VPORT/f1k
#   # web-1k-close เพิ่ม -H Connection:close   sat ใช้ -R 2000000 (closed-loop)   rate = C0 × level ÷ 100 จาก c0.tsv
#
# ===== ขั้นตอน =====
# shellcheck disable=SC2086,SC2034   # แยกคำโดยตั้งใจ, rep ใช้ใน run_lib.sh
# shellcheck source=run_lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

# หนึ่งรอบ: <load> ที่ <level> (% ของ C0 หรือ sat) ผ่าน VIP
one_round() {
    local mode=$1 load=$2 level=$3 r0 r1 i
    round_begin $TEST-$mode-$load-${level%:*} $HTTP_DURATION "test=$TEST mode=$mode workload=$load \
$(level_meta equal $load $level)" || return 0
    # ขั้นที่ 1  รีเซ็ต B แล้วรอ SETTLE
    reset_b
    # ขั้นที่ 2  อ่านค่าก่อนยิง: request ที่ backend แต่ละตัวตอบไปแล้ว
    r0=$(cmd c "$C_REQUESTS")
    # ขั้นที่ 3  เก็บตัวนับก่อนยิง แล้วเริ่ม mpstat
    read_counters 0
    cpu_begin
    # ขั้นที่ 4  ยิง: wrk2 128 connection 40 s ไป VIP:8080/f1k  (-R = req/s ของ level  sat = -R 2000000)
    traffic via_vip $load ${level#*:}
    # ขั้นที่ 5  หยุด mpstat  เก็บตัวนับหลังยิง  ตรวจ rate
    cpu_end
    read_counters 1
    round_end
    # ขั้นที่ 6  อ่านค่าหลังยิงแล้วแสดง: request ต่อ backend และ CPU ของ B
    r1=$(cmd c "$C_REQUESTS")
    for i in 1 2 3; do delta "C backend $i requests" "$(field b$i <<< "$r0")" "$(field b$i <<< "$r1")"; done
    show_cpu b
}

t1_2() {
    local mode load level
    need_c0 equal web-1k web-1k-close
    for rep in $(seq $REPS_HTTP); do
        for mode in $TEST1_MODES; do
            # เตรียม: B$ setup_b_lb.sh mode <mode>   C$ setup_c_server.sh mode guarded (nft ipt = nat)
            use_mode $mode
            # รอบ idle 10 s ของ mode นี้
            idle_round $TEST-$mode "test=$TEST mode=$mode"
            for load in web-1k web-1k-close; do
                for level in $(levels equal $load "$TEST12_LEVELS") sat:sat; do one_round $mode $load $level; done
            done
        done
    done
    restore
}

run_one 1.2 "$@"
