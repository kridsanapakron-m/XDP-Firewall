#!/bin/bash
# ข้อ 0.2  C0 quota 100/50/25% (C0 ของข้อ 5)
#
# เป้าหมาย  C0 = throughput รวมเมื่อยิงตรงไป backend 3 ตัวพร้อมกันแบบ sat (LB ในอุดมคติ) ต่อ workload
# factor    workload = web-1k 10k 100k 1m mix, elephant
# คงที่     ไม่มี LB, wrk2 128 connection (แบ่ง 42/43/43), iperf 16 stream (5/5/6), 40 s, 10 rep
#           report.py สรุปเป็น RUN_DIR/c0.tsv  ข้ออื่นอ่าน C0 จากไฟล์นี้
# ผล        results/<ชุด>/<ข้อ>/<id>-r<rep>.{meta,client,a0,a1,b0,b1,c0,c1,cpu-{a,b,c}.json.gz}  และ report.txt
# รัน       sudo ./tcase/0.2.sh  |  ./tcase/0.2.sh plan  |  ./tcase/0.2.sh report [dir]
#           ปรับค่าผ่าน env เช่น REPS=1 DURATION=5 RUN_DIR=results/x sudo -E ./tcase/0.2.sh  (RESUME=1 ข้ามรอบที่เสร็จแล้ว)
#
# ===== การตั้งเครื่องของข้อนี้ =====
# สคริปต์ตั้งให้เองผ่าน setup_b_lb.sh / setup_c_server.sh  ข้างล่างคือคำสั่งที่ให้ผลเท่ากัน ใช้ทำมือได้
# ตั้งเครื่องครั้งแรก: ดูหัวไฟล์ tcase/run_lib.sh
# ดึงบล็อกออกมาเป็นคำสั่งพร้อมวาง (ลบ "#   " นำหน้า) เช่น  sed -n '/^# --- C: quota/,/^#$/s/^#   //p' tcase/0.2.sh
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
# --- C: quota ของ backend 1 2 3 = 100% 50% 25%  (C$ setup_c_server.sh quota 100% 50% 25%) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   q=(100% 50% 25%)
#   for i in 1 2 3; do systemctl set-property --runtime backend$i.scope CPUQuota=${q[i-1]} CPUQuotaPeriodSec=10ms; done
#
# --- A: ยิงตรงไป backend 3 ตัวพร้อมกัน (ตัวอย่าง web-1k sat 40 s  ชุดละ backend) ---
#   source <repo บน A>/Perf_t/perf_env.sh
#   for i in 1 2 3; do
#       c=$(( 128 * i / 3 - 128 * (i - 1) / 3 ))       # connection 42 43 43
#       wrk2 -t 2 -c $c -d 40s -R 2000000 --latency http://$(backend_ip $i):$VPORT/f1k > /tmp/c0-b$i.txt &
#   done; wait; grep -h 'Requests/sec' /tmp/c0-b*.txt
#   # ไฟล์อื่น: /f10k /f100k /f1m  web-mix เพิ่ม -s mix.lua (สคริปต์สร้างไว้ใน RUN_DIR)  web-1k-close เพิ่ม -H Connection:close
#   # elephant: iperf -c $(backend_ip $i) -p $IPERF_PORT -P <5 5 6> -t 40 -f m  (ชุดละ backend พร้อมกัน)
#
# ===== ขั้นตอน =====
# shellcheck disable=SC2086,SC2034   # แยกคำโดยตั้งใจ, rep ใช้ใน run_lib.sh
# shellcheck source=run_lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/run_lib.sh"

# หนึ่งรอบ: ยิงตรงไป backend 3 ตัวพร้อมกันแบบ sat ด้วย workload <load>
one_round() {
    local load=$1 r0 r1 i
    round_begin $TEST-$load $HTTP_DURATION "test=$TEST scenario=unequal workload=$load level=sat streams=$STREAMS $(http_meta)" ||
        return 0
    # ขั้นที่ 1  B ไม่อยู่ในเส้นทาง ไม่แตะ B (B_OFF_PATH) แล้วรอ SETTLE
    reset_b
    # ขั้นที่ 2  อ่านค่าก่อนยิง: request ที่ nginx ของ backend แต่ละตัวตอบไปแล้ว
    r0=$(cmd c "$C_REQUESTS")
    # ขั้นที่ 3  เก็บตัวนับก่อนยิงของ A B C (.a0 .b0 .c0) แล้วเริ่ม mpstat
    read_counters 0
    cpu_begin
    # ขั้นที่ 4  ยิง: 3 ชุดพร้อมกัน ชุดละ backend (wrk2 42/43/43 connection หรือ iperf 5/5/6 stream) แบบ sat
    traffic direct3 $load sat
    # ขั้นที่ 5  หยุด mpstat  เก็บตัวนับหลังยิง (.a1 .b1 .c1)  ตรวจ rate
    cpu_end
    read_counters 1
    round_end
    # ขั้นที่ 6  อ่านค่าหลังยิงแล้วแสดง: request ต่อ backend และ CPU ของ C
    r1=$(cmd c "$C_REQUESTS")
    for i in 1 2 3; do delta "C backend $i requests" "$(field b$i <<< "$r0")" "$(field b$i <<< "$r1")"; done
    show_cpu c
}

t0_2() {
    local load B_OFF_PATH=1
    # เตรียม: B ไม่มี LB, C ให้ A ยิงตรงไป backend ได้, quota ของ scenario unequal
    on_c mode direct
    on_c quota ${QUOTA[unequal]} >/dev/null
    for rep in $(seq $REPS_HTTP); do
        for load in $(web_loads) elephant; do one_round $load; done
    done
    restore                                             # คืน B = xdp, C = guarded, quota 100%
}

run_one 0.2 "$@"
