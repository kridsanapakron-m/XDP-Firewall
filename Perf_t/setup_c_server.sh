#!/bin/bash
# เครื่อง C (server): backend 3 ตัวใน netns + ตัวถอด IPIP + nginx และ iperf ใน cgroup + agent ของ AWFD
#
# ใช้:  ./setup_c_server.sh up                สร้างใหม่ทั้งหมด (ลบของเดิมก่อน)
#       ./setup_c_server.sh down              ลบทิ้งทั้งหมด
#       ./setup_c_server.sh mode guarded      DSR และ proxy: กันไม่ให้ A ต่อตรงไป backend (ค่าเริ่มต้น)
#       ./setup_c_server.sh mode nat          nftables/iptables DNAT: ขากลับไปทาง B
#       ./setup_c_server.sh mode direct       ข้อ 0, 1.4, 3.0: A ยิงตรงไป backend
#       ./setup_c_server.sh quota 100% 50% 25%    CPUQuota ของ backend 1 2 3 (100% = 1 core)
#       ./setup_c_server.sh probe-drop 10     ทิ้ง probe ของ AWFD 10% (ข้อ 5)
#       ./setup_c_server.sh snapshot          ตัวนับของ C (run_tests.sh ใช้)
#       ./setup_c_server.sh cpu start|stop    mpstat ของ C ช่วงยิง  stop พิมพ์ JSON (run_tests.sh ใช้)
#       ./setup_c_server.sh sample <วินาที>   ตัวนับต่อ backend ทุก 1 วินาที (ข้อ 4.3)
#       ./setup_c_server.sh env | status
# shellcheck disable=SC2086,SC2046,SC2206,SC1090   # ตั้งใจให้แยกคำ: ค่าหลายคำ เช่น QUOTA, รายการ VIP, argument ของเครื่องมือ
set -e

SCRIPT_DIR=$(realpath "$(dirname "$0")")
# shellcheck source=perf_env.sh
source "$SCRIPT_DIR/perf_env.sh"
STATE=/run/perf_c.state         # เก็บ mode และ probe-drop ไว้สร้างกฎ firewall ใหม่ทุกครั้ง
DEFAULT_QUOTA=100%
# CFS ตัด CPU เป็นช่วงละ period  ค่าเริ่มต้น 100 ms ทำให้ backend ที่ quota 10% หยุดทีละ 90 ms แม้ยังไม่เต็ม
# จน p99 เพี้ยน  10 ms ให้หยุดถี่ขึ้นแต่สั้นลง
QUOTA_PERIOD=10ms

cgroup_of() { echo /sys/fs/cgroup/system.slice/backend$1.scope; }

check_tools() {
    for tool in nginx iperf nft clang make systemd-run nsenter taskset curl ethtool mpstat; do
        command -v $tool >/dev/null || { echo "ไม่พบ $tool  ดู 00_overview.txt หัวข้อ 9"; exit 1; }
    done
}

build() {
    make -C "$REPO" xdp_lb_deencap.o xdp_lb_agent >/dev/null
}

kernel_settings() {
    sysctl -qw net.ipv4.ip_forward=1
    for scope in all default $SERVER_IFACE; do
        sysctl -qw net.ipv4.conf.$scope.rp_filter=0
        sysctl -qw net.ipv4.conf.$scope.accept_redirects=0
        sysctl -qw net.ipv4.conf.$scope.send_redirects=0
    done
}

make_files() {
    mkdir -p $WEBROOT
    for size in 1k:1 10k:10 100k:100 1m:1024; do
        [ -f $WEBROOT/f${size%%:*} ] || dd if=/dev/urandom of=$WEBROOT/f${size%%:*} bs=1024 count=${size##*:} status=none
    done
}

make_backend() {
    local i=$1 namespace=server_$1
    ip netns add $namespace
    ip link add vh$i type veth peer name vn$i
    ip link set vn$i netns $namespace
    ip addr add $(backend_host_ip $i)/30 dev vh$i
    ip link set vh$i up mtu 1600
    sysctl -qw net.ipv4.conf.vh$i.rp_filter=0

    ip -n $namespace link set lo up
    ip -n $namespace addr add $(backend_ip $i)/30 dev vn$i
    ip -n $namespace link set vn$i up mtu 1600
    ip -n $namespace route add default via $(backend_host_ip $i) dev vn$i
    ip -n $namespace addr add $VIP/32 dev lo
    # xdp_lb_deencap ถอดแค่ IPIP ไม่แก้ dst  VIP ชุดของข้อ 2 จึงต้องเป็น local ด้วย ไม่งั้นถูกทิ้งก่อนถึงตัวนับ
    ip -n $namespace route add local 10.100.0.0/16 dev lo
    ip netns exec $namespace sysctl -qw net.ipv4.conf.all.rp_filter=0 \
        net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.all.arp_announce=2
    ip -n $namespace link set dev vn$i xdpgeneric obj "$REPO/xdp_lb_deencap.o" sec xdp

    # UDP ที่เข้า backend ถูกนับแล้วทิ้ง จะได้ไม่มี ICMP port unreachable ย้อนกลับไปหา A
    # udp_frag_in นับ datagram (ประกอบ fragment แล้ว) จาก A ที่ port VPORT_FRAG  flood ของข้อ 3.5 ไม่ถูกนับ
    ip netns exec $namespace nft -f - <<NFT
table inet perf_sink {
    counter udp_in {}
    counter udp_frag_in {}
    chain input {
        type filter hook input priority 0; policy accept;
        udp dport $VPORT counter name udp_in drop
        ip saddr $CLIENT_IP udp dport $VPORT_FRAG counter name udp_frag_in drop
        udp dport $VPORT_FRAG drop
    }
}
NFT
}

start_nginx() {
    local i=$1 config=/etc/nginx/perf-backend-$1.conf
    mkdir -p /tmp/perf-nginx-$i
    cat > $config <<NGINX
worker_processes 1;
worker_rlimit_nofile 65536;
pid /run/perf-nginx-$i.pid;
error_log /var/log/perf-nginx-$i.err warn;
events { worker_connections 8192; }
http {
    access_log off;
    sendfile on;
    keepalive_requests $KEEPALIVE_REQS;
    default_type application/octet-stream;
    client_body_temp_path /tmp/perf-nginx-$i/body;
    proxy_temp_path       /tmp/perf-nginx-$i/proxy;
    fastcgi_temp_path     /tmp/perf-nginx-$i/fastcgi;
    uwsgi_temp_path       /tmp/perf-nginx-$i/uwsgi;
    scgi_temp_path        /tmp/perf-nginx-$i/scgi;
    server {
        listen $VIP:$VPORT backlog=8192 reuseport;
        listen $(backend_ip $i):$VPORT backlog=8192 reuseport;
        root $WEBROOT;
        location = /id { return 200 "backend-$i\n"; }
        location = /nginx_status { stub_status; allow $(backend_ip $i); deny all; }
    }
}
NGINX
    # nginx และ iperf อยู่ใน scope เดียวกัน CPUQuota จึงจำกัดทั้งคู่  backend i ใช้ core 4+i เท่านั้น
    # --scope เพราะทั้งสองตัว fork เป็น daemon  ถ้าเป็น service ธรรมดา systemd จะฆ่าทิ้ง
    # stdin/stdout/stderr ของ daemon ต้องไม่ใช่ของ ssh ที่สั่งมา ไม่งั้น ssh ค้างรอ daemon ปิด
    systemd-run --quiet --scope --unit backend$i -p AllowedCPUs=$(backend_cpus $i) \
        -p CPUQuota=$DEFAULT_QUOTA -p CPUQuotaPeriodSec=$QUOTA_PERIOD sh -c "ip netns exec server_$i nginx -c $config &&
            ip netns exec server_$i iperf -s -p $IPERF_PORT -D" \
        < /dev/null >> /var/log/perf-backend-$i.log 2>&1 || { tail -5 /var/log/perf-backend-$i.log; exit 1; }
}

start_agent() {
    local i=$1
    setsid taskset -c $AGENT_CPU nsenter --net=/var/run/netns/server_$i -- \
        "$REPO/xdp_lb_agent" $(backend_ip $i) $(cgroup_of $i) >/var/log/perf-agent-$i.log 2>&1 < /dev/null &
    echo $! > /run/perf-agent-$i.pid
}

# กฎ firewall บน C สร้างใหม่ทั้งชุดจาก mode และ probe-drop ล่าสุด
apply_firewall() {
    local mode=guarded drop=0
    [ -f $STATE ] && source $STATE
    nft delete table inet perf_guard 2>/dev/null || true
    {
        # nft ต้องมีขึ้นบรรทัดใหม่ (หรือ ;) หลังกฎและหลัง } ทุกตัว
        echo "table inet perf_guard {"
        echo "chain forward {"
        echo "type filter hook forward priority 0; policy accept;"
        [ "$drop" -gt 0 ] && echo "udp dport $AGENT_PORT numgen random mod 100 < $drop drop"
        [ $mode = guarded ] && echo "ip saddr $CLIENT_IP ip daddr 192.168.200.0/22 ct state new drop"
        echo "}"
        echo "}"
    } | nft -f -
    if [ $mode = nat ]; then
        ip route replace $CLIENT_IP/32 via $LB_IP dev $SERVER_IFACE
    else
        ip route del $CLIENT_IP/32 via $LB_IP 2>/dev/null || true
    fi
}

set_state() {
    local mode=guarded drop=0
    [ -f $STATE ] && source $STATE
    eval "$1=$2"
    printf 'mode=%s\ndrop=%s\n' $mode $drop > $STATE
    apply_firewall
}

set_quota() {
    for i in $BACKENDS; do
        systemctl set-property --runtime backend$i.scope CPUQuota=${1:-$DEFAULT_QUOTA} CPUQuotaPeriodSec=$QUOTA_PERIOD
        shift || true
    done
    echo "quota_ns=$(date +%s%N)"       # เวลาที่ quota เปลี่ยนจริง (นาฬิกาของ C เดียวกับ sample)
}

down() {
    for i in $BACKENDS; do
        [ -f /run/perf-agent-$i.pid ] && kill $(cat /run/perf-agent-$i.pid) 2>/dev/null || true
        rm -f /run/perf-agent-$i.pid
        systemctl stop backend$i.scope 2>/dev/null || true
        ip netns pids server_$i 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del server_$i 2>/dev/null || true
        ip link del vh$i 2>/dev/null || true
    done
    nft delete table inet perf_guard 2>/dev/null || true
    ip route del $CLIENT_IP/32 via $LB_IP 2>/dev/null || true
    rm -f $STATE
}

up() {
    check_tools
    build
    down
    tune_machine $SERVER_IFACE
    kernel_settings
    make_files
    for i in $BACKENDS; do
        make_backend $i
        start_nginx $i
        start_agent $i
    done
    apply_firewall
    status
}

nft_packets() {
    ip netns exec server_$1 nft list counter inet perf_sink $2 |
        awk '{for (f = 1; f < NF; f++) if ($f == "packets") print $(f + 1)}'
}

backend_counters() {
    local i cgroup
    for i in $BACKENDS; do
        cgroup=$(cgroup_of $i)
        echo "b${i}_cpu_usec=$(awk '$1 == "usage_usec" {print $2}' $cgroup/cpu.stat)"
        echo "b${i}_throttled_usec=$(awk '$1 == "throttled_usec" {print $2}' $cgroup/cpu.stat)"
        echo "b${i}_quota_pct=$(awk '{print $1 == "max" ? 0 : int($1 * 100 / $2)}' $cgroup/cpu.max)"
        echo "b${i}_rx_packets=$(cat /sys/class/net/vh$i/statistics/tx_packets)"
        # request ที่ nginx ตอบแล้ว (stub_status บรรทัดที่ 3 ช่องที่ 3)  การอ่านนี้นับเพิ่ม 1 request
        echo "b${i}_requests=$(ip netns exec server_$i curl -s --max-time 1 \
            http://$(backend_ip $i):$VPORT/nginx_status | awk 'NR == 3 {print $3}')"
    done
}

snapshot() {
    host_snapshot $SERVER_IFACE
    backend_counters
    for i in $BACKENDS; do
        echo "b${i}_udp=$(nft_packets $i udp_in)"
        echo "b${i}_udp_frag=$(nft_packets $i udp_frag_in)"
    done
}

# ทุก 1 วินาทีหนึ่งบรรทัด: time_ns และตัวนับของ backend (key=value คั่นด้วยช่องว่าง)
sample() {
    local n
    for ((n = 0; n <= $1; n++)); do
        echo "time_ns=$(date +%s%N) $(backend_counters | tr '\n' ' ')"
        sleep 1
    done
}

status() {
    cat $STATE 2>/dev/null || echo "mode=guarded drop=0"
    for i in $BACKENDS; do
        printf 'backend-%s  %s  quota=%s  agent=%s  ' $i $(backend_ip $i) \
            "$(cat $(cgroup_of $i)/cpu.max 2>/dev/null)" \
            "$(kill -0 $(cat /run/perf-agent-$i.pid 2>/dev/null) 2>/dev/null && echo run || echo stop)"
        ip netns exec server_$i curl -s --max-time 2 http://$VIP:$VPORT/id || echo "nginx ไม่ตอบ"
        if ! kill -0 $(cat /run/perf-agent-$i.pid 2>/dev/null) 2>/dev/null; then
            echo "  agent-$i: $(tail -1 /var/log/perf-agent-$i.log 2>/dev/null)"
        fi
    done
}

env_c() {
    env_info $SERVER_IFACE
    echo "== backend"
    for i in $BACKENDS; do
        echo "backend$i cpus=$(cat $(cgroup_of $i)/cpuset.cpus 2>/dev/null) cpu.max=$(cat $(cgroup_of $i)/cpu.max 2>/dev/null)"
        ip -n server_$i -br link 2>/dev/null || true
    done
    echo "agent_cpu=$AGENT_CPU"
    echo "nginx_keepalive_requests=$(awk '/keepalive_requests/ {print $2 + 0}' /etc/nginx/perf-backend-1.conf)"
    cat $STATE 2>/dev/null || true
}

require_root
case "$1" in
    up)         up ;;
    down)       down ;;
    mode)       [[ "$2" =~ ^(guarded|nat|direct)$ ]] || { echo "mode: guarded|nat|direct"; exit 1; }
                set_state mode $2 ;;
    quota)      shift; set_quota "$@" ;;
    probe-drop) [[ "$2" =~ ^[0-9]+$ ]] || { echo "probe-drop: เปอร์เซ็นต์ 0-100"; exit 1; }
                set_state drop $2 ;;
    snapshot)   snapshot ;;
    cpu)        [[ "$2" =~ ^(start|stop)$ ]] || { echo "cpu start|stop"; exit 1; }
                cpu_$2 ;;
    sample)     sample "${2:-60}" ;;
    env)        env_c ;;
    status)     status ;;
    *)          sed -n '2,14p' "$0"; exit 1 ;;
esac
