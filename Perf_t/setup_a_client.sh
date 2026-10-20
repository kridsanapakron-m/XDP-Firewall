#!/bin/bash
# เครื่อง A (client): route, ตรวจเครื่องมือยิง traffic (pktgen hping3 wrk2/h2load iperf), ส่งสคริปต์ไป B และ C
#
# ใช้:  ./setup_a_client.sh up      ตั้งเครื่อง + ตรวจเครื่องมือ + ตรวจ ssh ไป B และ C
#       ./setup_a_client.sh push    copy สคริปต์ไปไว้ที่ $PERF_DIR บน B และ C
#       ./setup_a_client.sh check   ตรวจว่า VIP ตอบ และกระจายครบ 3 backend
# shellcheck disable=SC2086,SC2046,SC2206   # ตั้งใจให้แยกคำ: ค่าหลายคำ เช่น QUOTA, รายการ VIP, argument ของเครื่องมือ
set -e

SCRIPT_DIR=$(realpath "$(dirname "$0")")
# shellcheck source=perf_env.sh
source "$SCRIPT_DIR/perf_env.sh"

check_tools() {
    for tool in iperf hping3 python3 ssh scp curl shuf ethtool mpstat; do
        command -v $tool >/dev/null || { echo "ไม่พบ $tool  ดู 00_overview.txt หัวข้อ 9"; exit 1; }
    done
    command -v wrk2 >/dev/null || command -v h2load >/dev/null || { echo "ไม่พบทั้ง wrk2 และ h2load"; exit 1; }
    command -v wrk2 >/dev/null || echo "ไม่พบ wrk2  ข้อที่เป็น HTTP จะใช้ h2load --rps แทน"
    command -v tcpreplay >/dev/null || echo "ไม่พบ tcpreplay  ใช้ RAW_TOOL=tcpreplay ไม่ได้"
    modprobe pktgen || { echo "โหลด pktgen ไม่ได้  ดู 00_overview.txt หัวข้อ 9"; exit 1; }
}

push() {
    for host in $SSH_LB $SSH_SERVER; do
        ssh -o BatchMode=yes $host "mkdir -p $PERF_DIR"
        scp -q "$SCRIPT_DIR"/perf_env.sh "$SCRIPT_DIR"/setup_b_lb.sh "$SCRIPT_DIR"/setup_c_server.sh $host:$PERF_DIR/
        echo "copy ไป $host:$PERF_DIR แล้ว"
    done
}

up() {
    require_root
    check_tools
    for scope in all default $CLIENT_IFACE; do
        sysctl -qw net.ipv4.conf.$scope.rp_filter=0
        sysctl -qw net.ipv4.conf.$scope.accept_redirects=0
    done
    # TCP ไป VIP ใช้ MTU 1480: ห่อ IPIP แล้วยังไม่เกิน 1500 ไม่ต้องพึ่ง PMTU ของ LB (xdp ปิด pmtu อยู่)
    # ทาง direct ไป backend ตั้งเท่ากัน ขนาด segment ของ C0 จะได้ตรงกับตอนผ่าน LB
    ip route replace $VIP/32 dev $CLIENT_IFACE mtu lock $VIP_MTU
    ip route replace 192.168.200.0/22 via $SERVER_IP dev $CLIENT_IFACE mtu lock $VIP_MTU
    for host in $SSH_LB $SSH_SERVER; do
        ssh -o BatchMode=yes -o ConnectTimeout=3 $host true || { echo "ssh ไป $host ไม่ได้  ตั้ง ssh key ก่อน"; exit 1; }
    done
    local lb_mac
    lb_mac=$(mac_of $LB_IP)
    [ -n "$lb_mac" ] || { echo "หา MAC ของ $LB_IP ไม่ได้"; exit 1; }
    echo "A พร้อม  MAC ของ B = $lb_mac"
    ip route get $VIP
}

check() {
    for try in 1 2 3; do
        curl -s --max-time 3 http://$VIP:$VPORT/id && break
        [ $try = 3 ] && { echo "VIP ไม่ตอบ HTTP"; exit 1; }
        sleep 1
    done
    for _ in $(seq 30); do curl -s --max-time 2 http://$VIP:$VPORT/id; done | sort | uniq -c
    iperf -c $VIP -p $IPERF_PORT -t 2 -f m | tail -1 || echo "VIP ไม่ตอบ iperf"
}

case "$1" in
    up)    up ;;
    push)  push ;;
    check) check ;;
    *)     sed -n '2,6p' "$0"; exit 1 ;;
esac
