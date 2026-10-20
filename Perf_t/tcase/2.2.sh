#!/bin/bash
# ข้อ 2.2  เวลาเลือก rule: nft (map)
#
# เป้าหมาย  เวลาที่ใช้เลือก rule ต่อ packet เมื่อจำนวน VIP เพิ่ม: nftables verdict map  จับเวลา nft_do_chain ของ table perf_lb ด้วย bpftrace
# factor    VIP = 1 10 100 1000 (ชุด 10.100.0.x  VIP ละ 1 backend)   pattern = spread (ทุก VIP), last (VIP ตัวสุดท้าย)
# คงที่     UDP 64 B 40k pps flow NEW (ทุก packet เป็น packet แรกของ flow ต้องหา rule), 20 s, 10 rep, bpf_stats เปิด
# ผล        results/<ชุด>/<ข้อ>/<id>-r<rep>.{meta,client,a0,a1,b0,b1,c0,c1,cpu-{a,b,c}.json.gz}  + .lookup  และ report.txt
# รัน       sudo ./tcase/2.2.sh  |  ./tcase/2.2.sh plan  |  ./tcase/2.2.sh report [dir]
#           ปรับค่าผ่าน env เช่น REPS=1 DURATION=5 RUN_DIR=results/x sudo -E ./tcase/2.2.sh  (RESUME=1 ข้ามรอบที่เสร็จแล้ว)
#
# ===== การตั้งเครื่องของข้อนี้ =====
# สคริปต์ตั้งให้เองผ่าน setup_b_lb.sh / setup_c_server.sh  ข้างล่างคือคำสั่งที่ให้ผลเท่ากัน ใช้ทำมือได้
# ตั้งเครื่องครั้งแรก: ดูหัวไฟล์ tcase/run_lib.sh
# ดึงบล็อกออกมาเป็นคำสั่งพร้อมวาง (ลบ "#   " นำหน้า) เช่น  sed -n '/^# --- C: quota/,/^#$/s/^#   //p' tcase/2.2.sh
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
# --- B: mode nft ชุด N VIP  (B$ setup_b_lb.sh mode nft <N>)  verdict map: VIP -> backend (ค้นแบบ hash) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   N=1000                                         # 1 10 100 1000
#   sysctl -w net.netfilter.nf_conntrack_max=1048576
#   {
#       echo "table ip perf_lb {"
#       echo "map vip_backend {"
#       echo "type ipv4_addr : ipv4_addr"
#       echo "elements = {"
#       for ((k = 0; k < N; k++)); do
#           if [ $k -gt 0 ]; then echo ","; fi
#           printf '%s : %s' $(ip_add $MULTI_VIP_FIRST $k) $(backend_ip $(( k % 3 + 1 )))
#       done
#       printf '\n}\n}\n'
#       echo "chain prerouting {"
#       echo "type nat hook prerouting priority dstnat;"
#       echo "udp dport $VPORT dnat to ip daddr map @vip_backend"
#       echo "}"
#       echo "}"
#   } | nft -f -
#
# --- B: จับเวลา nft_do_chain ช่วงยิง  (B$ setup_b_lb.sh lookup start  แล้ว  lookup stop  -> <id>.lookup) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   bpftrace -e 'kfunc:nf_tables:nft_do_chain /str(((struct nft_chain *)args->priv)->table->name) == "perf_lb"/ { @start[cpu] = nsecs; }
#   kretfunc:nf_tables:nft_do_chain /@start[cpu]/ { @lookup_ns = sum(nsecs - @start[cpu]); @lookup_calls = count(); delete(@start[cpu]); }'
#   # รอจนพิมพ์ Attaching ... แล้วค่อยยิง  ยิงเสร็จกด Ctrl-C: พิมพ์ @lookup_calls และ @lookup_ns (ns รวม)
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
# --- A: ยิงหนึ่งรอบด้วย pktgen  (ตัวอย่าง VIP 1000 ตัว แบบ spread  flow NEW 40k pps 20 s) ---
#   source <repo บน A>/Perf_t/perf_env.sh
#   SIZE=64 PPS=40000 SEC=20 PORTS=64511 DST=$MULTI_VIP_FIRST DST_COUNT=1000 MAC=$(mac_of $LB_IP)
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
# --- A: pattern last ---
#   # DST=$(ip_add $MULTI_VIP_FIRST $((N - 1))) DST_COUNT=1  (ยิง VIP ตัวสุดท้ายตัวเดียว)
#
# ===== ขั้นตอน =====
# shellcheck disable=SC2086,SC2034   # แยกคำโดยตั้งใจ, rep ใช้ใน run_lib.sh
# shellcheck source=run_lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

# หนึ่งรอบ: ชุด <count> VIP แบบ <pattern>
one_round() {
    local count=$1 pattern=$2 dst=$MULTI_VIP_FIRST dst_count=$1 rx0 rx1 lk
    if [ $pattern = last ]; then dst=$(ip_add $MULTI_VIP_FIRST $(( count - 1 ))) dst_count=1; fi
    round_begin $TEST-$count-$pattern $DURATION "test=$TEST mode=nft vips=$count pattern=$pattern pps=$TEST2_PPS \
size=64 $(flow_meta new $NEW_PORTS)" || return 0
    # ขั้นที่ 1  รีเซ็ต B: โหลด rule ชุด <count> VIP ใหม่ + conntrack -F แล้วรอ SETTLE
    reset_b
    # ขั้นที่ 2  อ่านค่าก่อนยิง
    rx0=$(cmd b "$B_NIC/rx_packets")
    # ขั้นที่ 3  เก็บตัวนับก่อนยิง แล้วเริ่ม mpstat
    read_counters 0
    cpu_begin
    # ขั้นที่ 4  ยิง: (nft ipt) เริ่ม bpftrace → pktgen 64 B 40k pps 20 s flow NEW ไปชุด VIP → หยุด bpftrace ผลลง .lookup
    traffic traced pktgen dst_mac=$LB_MAC dst=$dst dst_count=$dst_count size=64 pps=$TEST2_PPS seconds=$DURATION \
        ports=$NEW_PORTS
    # ขั้นที่ 5  หยุด mpstat  เก็บตัวนับหลังยิง  ตรวจ rate
    cpu_end
    read_counters 1
    round_end
    # ขั้นที่ 6  อ่านค่าหลังยิงแล้วแสดง
    rx1=$(cmd b "$B_NIC/rx_packets")
    lk=$(cmd a "cat $out.lookup")
    delta "B rx_packets" "$rx0" "$rx1"
    ratio "ns ต่อครั้ง (lookup_ns ÷ calls)" 0 "$(field lookup_ns <<< "$lk")" 0 "$(field lookup_calls <<< "$lk")"
    ratio "ครั้งต่อ packet (calls ÷ rx)" 0 "$(field lookup_calls <<< "$lk")" "$rx0" "$rx1"
}

t2_2() {
    local count pattern
    # เตรียม: เปิด bpf_stats (B$ setup_b_lb.sh bpf-stats on)
    on_b bpf-stats on
    for rep in $(seq $REPS_TEST2); do
        for count in $VIP_COUNTS; do
            # เตรียม: B$ setup_b_lb.sh mode nft <count>   C$ setup_c_server.sh mode nat
            use_mode nft $count
            for pattern in spread last; do one_round $count $pattern; done
        done
    done
    on_b bpf-stats off
    restore
}

run_one 2.2 "$@"
