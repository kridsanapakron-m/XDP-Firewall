#!/bin/bash
# ค่าที่สคริปต์ทุกตัวใน Perf_t ใช้ร่วมกัน  แก้ให้ตรงกับเครื่องจริงก่อนใช้
# ไฟล์นี้ถูก source โดย setup_*.sh และ run_tests.sh  ไม่ได้รันตรง ๆ
# shellcheck disable=SC2034,SC2013   # ตัวแปรถูกใช้ในสคริปต์ที่ source ไฟล์นี้, IRQ อ่านทีละคำโดยตั้งใจ

# --- เครื่องและ interface ที่ต่อ switch (ดูชื่อจริงด้วย ip -br link) ---
CLIENT_IP=192.168.100.10
LB_IP=192.168.100.20            # ต้องตรงกับ device_ip ที่ฝังใน xdp_lb_ctl.c
SERVER_IP=192.168.100.30
CLIENT_IFACE=eno1
LB_IFACE=eno1
SERVER_IFACE=eno1

# ssh จาก A ไป B และ C  (ใช้ IP ของใบจัดการแทนได้ถ้ามี จะได้ไม่ปน traffic ทดสอบ)
SSH_LB=root@$LB_IP
SSH_SERVER=root@$SERVER_IP

# --- service ---
VIP=192.168.100.100             # ตั้งจริงบน LB_IFACE ของ B
VPORT=8080                      # HTTP (nginx) และ UDP (pktgen, hping3)
VPORT_FRAG=8081                 # UDP ที่เป็น fragment (ข้อ 3.3, 3.5) แยก port ไว้นับการส่งถึง
IPERF_PORT=5001                 # iperf server ใน backend แต่ละตัว
MULTI_VIP_FIRST=10.100.0.1      # VIP ชุดของข้อ 2 (ไล่ทีละหนึ่ง)  backend รับ 10.100.0.0/16 เป็น local
FLOW_SRC_BASE=10.200.0.1        # source IP ของ pktgen  thread t ใช้ 125 ตัวตั้งแต่ base + 125t
VIP_MTU=1480                    # MTU ของ route ไป VIP บน A  ห่อ IPIP แล้วไม่เกิน 1500

# --- backend บนเครื่อง C ---
BACKENDS="1 2 3"
backend_ip() { echo "192.168.20$1.2"; }
backend_host_ip() { echo "192.168.20$1.1"; }
# core ของ C: IRQ ของ NIC ใช้ core 0..QUEUES-1, agent core 4, backend i core 4+i (5, 6, 7) ตัวละ 1 core
AGENT_CPU=4
backend_cpus() { echo $((4 + $1)); }
DAEMON_CPU=4                    # core ของ xdp_lb_awfd บน B (นอก core ของ IRQ)
AGENT_PORT=9900                 # ต้องตรงกับ AWFD_AGENT_PORT ใน xdp_lb_common.h
KEEPALIVE_REQS=${KEEPALIVE_REQS:-100}   # nginx ปิด connection ทุก 100 request ให้มี connection ใหม่ตลอดรอบ

# --- path ---
REPO=/root/XDP-Firewall         # repo ที่ build แล้วบนเครื่อง B และ C
PERF_DIR=$REPO/Perf_t           # ที่วางสคริปต์ชุดนี้บน B และ C (setup_a_client.sh push)
PIN=/sys/fs/bpf/xdp_lb_test     # xdp_lb_ctl และ xdp_lb_awfd ฝัง path นี้ไว้
MAPS=$PIN/maps
WEBROOT=/srv/bench
QUEUES=${QUEUES:-4}             # จำนวนคิว RSS ของ NIC ที่ B และ C ใช้ทุกการทดสอบ
TUNE_NIC=${TUNE_NIC:-1}         # 0 = ไม่ปรับคิวและ rx-flow-hash ของ NIC (ixgbe X540 ของ B หลุดจาก PCIe หลังปรับ)

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "ต้องรันด้วย root (sudo -i หรือ sudo $0 ...)"
        exit 1
    fi
}

# IP ที่ห่างจาก $1 ไป $2 ตำแหน่ง เช่น ip_add 10.100.0.1 300 -> 10.100.1.45
ip_add() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    local n=$(( (a << 24 | b << 16 | c << 8 | d) + $2 ))
    echo "$((n >> 24 & 255)).$((n >> 16 & 255)).$((n >> 8 & 255)).$((n & 255))"
}

# MAC ของเครื่องใน subnet ทดสอบ (ใช้บน A)  ping ก่อนเพื่อให้มี neighbor
mac_of() {
    ping -c 1 -W 1 "$1" >/dev/null || true
    ip neigh show "$1" dev "$CLIENT_IFACE" | awk '{for (i = 1; i < NF; i++) if ($i == "lladdr") {print $(i + 1); exit}}'
}

# คิวของ NIC ใช้จำนวนเท่ากันทุกรอบ, IRQ ของแต่ละคิวผูกกับ core 0.. ตามลำดับ,
# RSS ของ UDP และ TCP hash ทั้ง IP และ port (sdfn) เพื่อให้ flow กระจายทุกคิว
tune_machine() {
    local iface=$1 core=0 irq governor
    for governor in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        [ -w "$governor" ] && echo performance > "$governor"
    done
    systemctl stop irqbalance 2>/dev/null || true
    if [ "$TUNE_NIC" = 1 ]; then
        ethtool -L "$iface" combined "$QUEUES" 2>/dev/null || echo "ปรับจำนวนคิวของ $iface ไม่ได้ ใช้ค่าเดิม"
    fi
    for irq in $(awk -v dev="$iface" '$0 ~ dev {sub(":", "", $1); print $1}' /proc/interrupts); do
        echo $((core % QUEUES)) > "/proc/irq/$irq/smp_affinity_list" 2>/dev/null || true
        core=$((core + 1))
    done
    for flow in udp4 tcp4; do
        if [ "$TUNE_NIC" = 1 ]; then
            ethtool -N "$iface" rx-flow-hash $flow sdfn 2>/dev/null || echo "ตั้ง rx-flow-hash $flow ของ $iface ไม่ได้"
        fi
        echo "rx-flow-hash $flow: $(ethtool -n "$iface" rx-flow-hash $flow 2>/dev/null | tr '\n' ' ')"
    done
    echo "tune: governor=performance  irqbalance หยุด  TUNE_NIC=$TUNE_NIC" \
         "$iface ใช้ $(ethtool -l "$iface" 2>/dev/null | awk '/^Current/ {c = 1} c && /^Combined/ {print $2; exit}') คิว"
}

# CPU ของทั้งเครื่องด้วย mpstat (sysstat) ทุก 1 วินาที แยก core และชนิด (usr sys irq soft ...)
# cpu_start ก่อนยิง  cpu_stop หลังยิง: SIGINT ให้ mpstat ปิด JSON ครบ (เก็บเฉพาะวินาทีที่ครบ) แล้วพิมพ์ JSON ออกมา
CPU_LOG=/run/perf-mpstat.json
cpu_start() {
    kill "$(cat /run/perf-mpstat.pid 2>/dev/null)" 2>/dev/null || true    # ตัวค้างจากรอบที่ถูกขัด
    S_TIME_FORMAT=ISO setsid mpstat -P ALL -o JSON 1 > $CPU_LOG 2>/dev/null < /dev/null &
    echo $! > /run/perf-mpstat.pid
}
cpu_stop() {
    local pid
    pid=$(cat /run/perf-mpstat.pid)
    kill -INT "$pid"
    while kill -0 "$pid" 2>/dev/null; do sleep 0.05; done
    cat $CPU_LOG
}

# ตัวนับของ NIC จาก /sys และ ethtool -S  (CPU วัดด้วย cpu_start / cpu_stop)
host_snapshot() {
    local iface=$1 counter
    for counter in rx_packets tx_packets rx_bytes tx_bytes rx_dropped tx_dropped rx_missed_errors; do
        echo "nic_$counter=$(cat "/sys/class/net/$iface/statistics/$counter")"
    done
    # rx ต่อคิว ชื่อตาม driver: igb/ixgbe rx_queue_0_packets, i40e rx-0.packets, mlx5 rx0_packets
    # และตัวนับ drop/miss ของ driver เก็บไว้ดูเอง (ethS_*)
    ethtool -S "$iface" 2>/dev/null | sed -nE \
        -e 's/^ *rx[_-]?(queue_)?([0-9]+)[._]packets: *([0-9]+)$/q\2_rx_packets=\3/p' \
        -e 's/^ *(rx[a-z0-9_]*(drop|miss|no_buf)[a-z0-9_]*): *([0-9]+)$/ethS_\1=\3/p'
    echo "time_ns=$(date +%s%N)"
}

# สภาพเครื่องที่มีผลต่อผลวัด  run_tests.sh เก็บเป็น RUN_DIR/env-{a,b,c}.txt ตอนเริ่ม  (คำสั่งไหนไม่มีก็ข้าม)
env_info() {
    local iface=$1 flow tool
    echo "== kernel";      uname -r
    echo "== driver";      ethtool -i "$iface" 2>&1 || true
    echo "== offload";     ethtool -k "$iface" 2>&1 || true
    echo "== channels";    ethtool -l "$iface" 2>&1 || true
    echo "== rings";       ethtool -g "$iface" 2>&1 || true
    echo "== rx-flow-hash"
    for flow in udp4 tcp4; do ethtool -n "$iface" rx-flow-hash $flow 2>&1 || true; done
    echo "== mtu";         ip -o link | awk '{print $2, $5}'
    echo "== conntrack";   sysctl -a 2>/dev/null | grep -E 'nf_conntrack_(max|buckets|udp_timeout)' || true
    echo "== bpf maps";    bpftool map show 2>/dev/null | grep -E 'name|max_entries' || true
    echo "== repo";        git -C "$REPO" rev-parse HEAD 2>/dev/null || true
    md5sum "$REPO"/*.o 2>/dev/null || true
    echo "== tools"
    for tool in wrk2 h2load iperf hping3 tcpreplay nginx haproxy ipvsadm nft iptables-legacy conntrack bpftrace; do
        if command -v $tool >/dev/null; then echo "$tool: $($tool --version 2>&1 | head -1)"; fi
    done
}
