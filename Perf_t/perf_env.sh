#!/bin/bash
CLIENT_IP=192.168.100.10
LB_IP=192.168.100.20
SERVER_IP=192.168.100.30
CLIENT_IFACE=eno1
LB_IFACE=enp1s0f0
SERVER_IFACE=eno1

SSH_LB=root@$LB_IP
SSH_SERVER=root@$SERVER_IP

VIP=192.168.100.100
VPORT=8080
VPORT_FRAG=8081
IPERF_PORT=5001
MULTI_VIP_FIRST=10.100.0.1
FLOW_SRC_BASE=10.200.0.1
VIP_MTU=1480

BACKENDS="1 2 3"
backend_ip() { echo "192.168.20$1.2"; }
backend_host_ip() { echo "192.168.20$1.1"; }
AGENT_CPU=4
backend_cpus() { echo $((4 + $1)); }
DAEMON_CPU=4
AGENT_PORT=9900
KEEPALIVE_REQS=${KEEPALIVE_REQS:-100}

REPO=/root/XDP-Firewall
PERF_DIR=$REPO/Perf_t
PIN=/sys/fs/bpf/xdp_lb_test
MAPS=$PIN/maps
WEBROOT=/srv/bench
QUEUES=${QUEUES:-4}
TUNE_NIC=${TUNE_NIC:-1}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "ต้องรันด้วย root (sudo -i หรือ sudo $0 ...)"
        exit 1
    fi
}

ip_add() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    local n=$(( (a << 24 | b << 16 | c << 8 | d) + $2 ))
    echo "$((n >> 24 & 255)).$((n >> 16 & 255)).$((n >> 8 & 255)).$((n & 255))"
}

mac_of() {
    ping -c 1 -W 1 "$1" >/dev/null || true
    ip neigh show "$1" dev "$CLIENT_IFACE" | awk '{for (i = 1; i < NF; i++) if ($i == "lladdr") {print $(i + 1); exit}}'
}

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

CPU_LOG=/run/perf-mpstat.json
cpu_start() {
    kill "$(cat /run/perf-mpstat.pid 2>/dev/null)" 2>/dev/null || true
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

host_snapshot() {
    local iface=$1 counter
    for counter in rx_packets tx_packets rx_bytes tx_bytes rx_dropped tx_dropped rx_missed_errors; do
        echo "nic_$counter=$(cat "/sys/class/net/$iface/statistics/$counter")"
    done
    ethtool -S "$iface" 2>/dev/null | sed -nE \
        -e 's/^ *rx[_-]?(queue_)?([0-9]+)[._]packets: *([0-9]+)$/q\2_rx_packets=\3/p' \
        -e 's/^ *(rx[a-z0-9_]*(drop|miss|no_buf)[a-z0-9_]*): *([0-9]+)$/ethS_\1=\3/p'
    echo "time_ns=$(date +%s%N)"
}

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
