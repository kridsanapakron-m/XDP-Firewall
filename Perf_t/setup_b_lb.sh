#!/bin/bash
# เครื่อง B (LB): VIP บน interface จริง + route ไป backend + สลับตัวเปรียบเทียบทีละแบบ
#
# ใช้:  ./setup_b_lb.sh up                     ตั้งเครื่อง แล้วเริ่มที่ mode xdp
#       ./setup_b_lb.sh mode <ชื่อ> [จำนวน VIP]  มีได้ทีละแบบ  ใส่จำนวน VIP = ชุด MULTI_VIP ของข้อ 2 (UDP อย่างเดียว)
#             xdp       xdp_lb (awfd) ของเรา        xdp-hash  xdp_lb ที่ใช้ find_backend เดิม
#             ipvs      IPVS โหมด tunnel            nft       nftables DNAT
#             ipt       iptables-legacy DNAT        nginx     nginx stream proxy (TCP + UDP)
#             haproxy   haproxy TCP proxy           none      ไม่มี LB
#       ./setup_b_lb.sh algo ecmp | wcmp [m] | lcf | awfd [m] [interval_ms]   (mode xdp)
#       ./setup_b_lb.sh algo rr | wlc|least_conn|leastconn <w1> <w2> <w3>   (ipvs | nginx | haproxy ข้อ 4  nft ipt แบ่งเท่ากันเท่านั้น)
#       ./setup_b_lb.sh feature fragment|pmtu on|off
#       ./setup_b_lb.sh reset [algo ...]     โหลด mode เดิมใหม่ + feature/algo เดิม + ล้าง conntrack/ipvs (ก่อนทุกรอบ)
#                                            ใส่ algo = บันทึก algo ใหม่ก่อน แล้ว daemon เริ่มครั้งเดียวตอน reset
#       ./setup_b_lb.sh bpf-stats on|off     เปิดตัวนับเวลาของ BPF (ข้อ 2, 3)
#       ./setup_b_lb.sh lookup start|stop    bpftrace จับเวลาหา rule ของ nft/ipt ช่วงยิง (ข้อ 2)  stop พิมพ์ lookup_*
#       ./setup_b_lb.sh snapshot             ตัวนับของ B (run_tests.sh ใช้)
#       ./setup_b_lb.sh cpu start|stop       mpstat ของ B ช่วงยิง  stop พิมพ์ JSON (run_tests.sh ใช้)
#       ./setup_b_lb.sh env | status | down [keep_vip]   keep_vip = ไม่ลบ VIP (ตอนคืนค่า: ลบแล้ว ixgbe ดับ)
# shellcheck disable=SC2086,SC2046,SC2206,SC1090   # ตั้งใจให้แยกคำ: ค่าหลายคำ เช่น QUOTA, รายการ VIP, argument ของเครื่องมือ
set -e

SCRIPT_DIR=$(realpath "$(dirname "$0")")
# shellcheck source=perf_env.sh
source "$SCRIPT_DIR/perf_env.sh"
MODE_FILE=/run/perf_b.mode      # "<mode> <จำนวน VIP หรือ ->"
STATE=/run/perf_b.state         # feature และ algo ล่าสุดของ mode xdp  reset ใช้ตั้งกลับ
CONFIG=/etc/xdp_lb/xdp_lb.json

check_tools() {
    for tool in clang make bpftool jq ipvsadm nft iptables-legacy-restore conntrack nginx haproxy ping ethtool mpstat \
        bpftrace; do
        command -v $tool >/dev/null || { echo "ไม่พบ $tool  ดู 00_overview.txt หัวข้อ 9"; exit 1; }
    done
}

# ชุด MULTI_VIP ของข้อ 2  ใช้รูปแบบเดียวกันตั้งแต่ 1 ตัว
vip_list() {
    for ((k = 0; k < $1; k++)); do ip_add $MULTI_VIP_FIRST $k; done
}

backend_of() { backend_ip $(( $1 % 3 + 1 )); }    # VIP ลำดับที่ k ของข้อ 2 ไป backend เดียว ทุก mode

stop_daemon() {
    [ -f /run/perf-awfd.pid ] && kill $(cat /run/perf-awfd.pid) 2>/dev/null || true
    rm -f /run/perf-awfd.pid
}

flush_awfd_map() {
    bpftool -j map dump pinned $MAPS/awfd_map | jq -r '.[].key | join(" ")' |
        while read -r key; do bpftool map delete pinned $MAPS/awfd_map key $key; done
}

# down_all [keep_xdp]: keep_xdp = ไม่ถอด XDP เพราะจะโหลดตัวใหม่ทับ (ถอด/ใส่ XDP ทำให้ ixgbe reset และ link หลุด)
down_all() {
    stop_daemon
    if [ "${1:-}" != keep_xdp ]; then
        bpftool net detach xdpdrv dev $LB_IFACE 2>/dev/null || true
        bpftool net detach xdpgeneric dev $LB_IFACE 2>/dev/null || true
    fi
    rm -rf $PIN
    ipvsadm -C 2>/dev/null || true
    modprobe -r ip_vs_rr ip_vs_wlc ip_vs 2>/dev/null || true     # ล้างตาราง connection ของ ipvs ด้วย
    nft delete table ip perf_lb 2>/dev/null || true
    iptables-legacy -t nat -D PREROUTING -j PERF_LB 2>/dev/null || true
    iptables-legacy -t nat -F PERF_LB 2>/dev/null || true
    iptables-legacy -t nat -X PERF_LB 2>/dev/null || true
    modprobe -r iptable_nat 2>/dev/null || true         # ตาราง nat ที่ว่างยังลง hook ให้ทุก connection ใหม่ของ mode อื่น
    for pid in /run/perf-lb-nginx.pid /run/perf-lb-haproxy.pid; do
        [ -f $pid ] && kill $(cat $pid) 2>/dev/null || true
        rm -f $pid
    done
    echo "none -" > $MODE_FILE
}

hash_object() {
    if [ ! /tmp/xdp_lb_hash.o -nt "$REPO/xdp_lb.c" ]; then
        sed 's/awfd(&flow, stats)/find_backend(\&flow)/' "$REPO/xdp_lb.c" > /tmp/xdp_lb_hash.c
        grep -q 'find_backend(&flow)' /tmp/xdp_lb_hash.c || { echo "แทน awfd() ใน xdp_lb.c ไม่ได้" >&2; exit 1; }
        clang -O2 -g -target bpf -I"$REPO" -I/usr/include/$(uname -m)-linux-gnu \
            -c /tmp/xdp_lb_hash.c -o /tmp/xdp_lb_hash.o
    fi
    echo /tmp/xdp_lb_hash.o
}

# service แบบ VIP เดียว: tcp/udp 8080, udp 8081 (fragment), tcp 5001  ทุกตัวมี backend 3 ตัว
# ชุด MULTI_VIP: udp 8080 อย่างเดียว VIP ลำดับที่ k มี backend เดียวคือ backend_of k
xdp_up() {
    local object=$REPO/xdp_lb.o count=$2 separator="" k=0 vip service
    [ $1 = xdp-hash ] && object=$(hash_object)
    mkdir -p $MAPS /etc/xdp_lb
    bpftool prog load $object $PIN/prog type xdp pinmaps $MAPS
    bpftool net attach xdpdrv pinned $PIN/prog dev $LB_IFACE overwrite    # แทนตัวเดิมโดยไม่ reset NIC
    {
        echo '{"fragment_handling": false, "icmp_pmtu": false, "services": ['
        if [ $count = - ]; then
            for service in tcp:$VPORT udp:$VPORT udp:$VPORT_FRAG tcp:$IPERF_PORT; do
                printf '%s{"vip": "%s", "port": %d, "protocol": "%s", "backends": ["%s", "%s", "%s"]}\n' \
                    "$separator" $VIP ${service#*:} ${service%%:*} $(backend_ip 1) $(backend_ip 2) $(backend_ip 3)
                separator=,
            done
        else
            for vip in $(vip_list $count); do
                printf '%s{"vip": "%s", "port": %d, "protocol": "udp", "backends": ["%s"]}\n' \
                    "$separator" $vip $VPORT $(backend_of $k)
                separator=, k=$((k + 1))
            done
        fi
        echo ']}'
    } > $CONFIG
    "$REPO/xdp_lb_ctl" apply
    echo "md5 ของ object: $(md5sum $object | cut -c1-12)"
}

# algo ของ ipvs nginx haproxy (ข้อ 4): "<scheduler> [น้ำหนักของ backend 1 2 3]"  ว่าง = แบ่งเท่ากัน น้ำหนัก 1
#   ตั้งใน STATE ผ่าน reset algo ... แล้ว load_mode อ่าน $algo ของ reset
lb_sched() {
    local sched
    read -r sched _ <<< "${algo:-}"
    [[ " $1 " == *" $sched "* ]] && echo $sched || echo ${1%% *}
}
lb_weight() {
    local weights
    read -r _ weights <<< "${algo:-}"
    weights=($weights)
    echo ${weights[$(( $1 - 1 ))]:-1}
}

ipvs_up() {
    local sched
    sched=$(lb_sched "rr wlc")
    modprobe ip_vs
    modprobe ipip
    for service in "-t $VIP:$VPORT" "-u $VIP:$VPORT" "-t $VIP:$IPERF_PORT"; do
        ipvsadm -A $service -s $sched
        for i in $BACKENDS; do ipvsadm -a $service -r $(backend_ip $i) -i -w $(lb_weight $i); done
    done
}

nft_up() {
    local count=$1 k=0
    sysctl -qw net.netfilter.nf_conntrack_max=1048576 2>/dev/null || true
    {
        echo "table ip perf_lb {"
        if [ $count = - ]; then
            echo "chain prerouting { type nat hook prerouting priority dstnat;"
            for match in "tcp dport { $VPORT, $IPERF_PORT }" "udp dport $VPORT"; do
                echo "ip daddr $VIP $match dnat to numgen inc mod 3 map {"
                echo "0 : $(backend_ip 1), 1 : $(backend_ip 2), 2 : $(backend_ip 3) }"
            done
            echo "}"
        else
            echo "map vip_backend {"
            echo "type ipv4_addr : ipv4_addr"
            echo "elements = {"
            for vip in $(vip_list $count); do
                [ $k -gt 0 ] && echo ","
                printf '%s : %s' $vip $(backend_of $k)
                k=$((k + 1))
            done
            printf '\n}\n}\n'
            echo "chain prerouting {"
            echo "type nat hook prerouting priority dstnat;"
            echo "udp dport $VPORT dnat to ip daddr map @vip_backend"
            echo "}"
        fi
        echo "}"
    } | nft -f -
}

ipt_up() {
    local count=$1 k=0
    sysctl -qw net.netfilter.nf_conntrack_max=1048576 2>/dev/null || true
    {
        echo "*nat"
        echo ":PERF_LB - [0:0]"
        echo "-A PREROUTING -j PERF_LB"
        if [ $count = - ]; then
            for match in "-d $VIP -p tcp -m multiport --dports $VPORT,$IPERF_PORT" "-d $VIP -p udp --dport $VPORT"; do
                echo "-A PERF_LB $match -m statistic --mode nth --every 3 --packet 0 -j DNAT --to-destination $(backend_ip 1)"
                echo "-A PERF_LB $match -m statistic --mode nth --every 2 --packet 0 -j DNAT --to-destination $(backend_ip 2)"
                echo "-A PERF_LB $match -j DNAT --to-destination $(backend_ip 3)"
            done
        else
            for vip in $(vip_list $count); do
                echo "-A PERF_LB -d $vip -p udp --dport $VPORT -j DNAT --to-destination $(backend_of $k)"
                k=$((k + 1))
            done
        fi
        echo "COMMIT"
    } | iptables-legacy-restore --noflush
}

nginx_up() {
    local config=/etc/nginx/perf-lb.conf module=/usr/lib/nginx/modules/ngx_stream_module.so
    {
        [ -f $module ] && echo "load_module $module;"
        echo "worker_processes auto; worker_rlimit_nofile 65536; pid /run/perf-lb-nginx.pid; error_log /var/log/perf-lb-nginx.err warn;"
        echo "events { worker_connections 16384; }"
        echo "stream {"
        for upstream in tcp:$VPORT udp:$VPORT iperf:$IPERF_PORT; do
            echo "upstream ${upstream%%:*}_backends {"
            [ "$(lb_sched "rr least_conn")" = least_conn ] && echo "least_conn;"
            for i in $BACKENDS; do echo "server $(backend_ip $i):${upstream##*:} weight=$(lb_weight $i);"; done
            echo "}"
        done
        echo "server { listen $VIP:$VPORT reuseport; proxy_pass tcp_backends; }"
        echo "server { listen $VIP:$IPERF_PORT reuseport; proxy_pass iperf_backends; }"
        echo "server { listen $VIP:$VPORT udp reuseport; proxy_pass udp_backends; proxy_responses 0; }"
        echo "}"
    } > $config
    # stdio ของ daemon ต้องไม่ใช่ของ ssh ที่สั่งมา ไม่งั้น ssh ค้างรอ daemon ปิด
    nginx -c $config < /dev/null >> /var/log/perf-lb-nginx.err 2>&1 || { tail -5 /var/log/perf-lb-nginx.err; exit 1; }
}

haproxy_up() {
    local config=/etc/haproxy/perf-lb.cfg
    mkdir -p /etc/haproxy
    {
        printf 'global\n    daemon\n    maxconn 200000\n    pidfile /run/perf-lb-haproxy.pid\n'
        printf 'defaults\n    mode tcp\n    timeout connect 5s\n    timeout client 60s\n    timeout server 60s\n'
        printf 'frontend vip\n    bind %s:%s,%s:%s\n    default_backend web\n' $VIP $VPORT $VIP $IPERF_PORT
        # server ที่ไม่ใส่ port ใช้ port เดียวกับที่ client ต่อเข้ามา (8080 หรือ 5001)
        printf 'backend web\n    balance %s\n' $(lb_sched "roundrobin leastconn")
        for i in $BACKENDS; do printf '    server b%s %s weight %s\n' $i $(backend_ip $i) $(lb_weight $i); done
    } > $config
    haproxy -f $config < /dev/null >> /var/log/perf-lb-haproxy.log 2>&1 || { tail -5 /var/log/perf-lb-haproxy.log; exit 1; }
}

# รอ link กลับมา แล้ว ping C ให้มี neighbor ของ C เพราะ bpf_fib_lookup ไม่ส่ง ARP เอง
wait_link() {
    for _ in $(seq 50); do
        if [ "$(cat /sys/class/net/$LB_IFACE/carrier 2>/dev/null)" = 1 ] && ping -c 1 -W 1 $SERVER_IP >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    echo "link ของ $LB_IFACE ไม่ขึ้น หรือ ping $SERVER_IP ไม่ได้" >&2
}

load_mode() {
    local mode=$1 count=${2:--}
    if [[ $mode == xdp* ]]; then down_all keep_xdp; else down_all; fi
    case $mode in
        xdp|xdp-hash) xdp_up $mode $count ;;
        ipvs)         ipvs_up ;;
        nft)          nft_up $count ;;
        ipt)          ipt_up $count ;;
        nginx)        nginx_up ;;
        haproxy)      haproxy_up ;;
        none)         ;;
        *)            echo "mode ไม่รู้จัก: $mode"; exit 1 ;;
    esac
    echo "$mode $count" > $MODE_FILE
    wait_link
}

set_mode() {
    load_mode "$@"
    printf 'fragment=off\npmtu=off\nalgo=ecmp\n' > $STATE     # mode ใหม่ = fragment, pmtu ปิด ไม่มี daemon
    echo "B mode=$(cat $MODE_FILE)"
}

set_state() {
    local fragment=off pmtu=off algo=ecmp
    [ -f $STATE ] && source $STATE
    eval "$1=\"$2\""
    printf 'fragment=%s\npmtu=%s\nalgo="%s"\n' $fragment $pmtu "$algo" > $STATE
}

set_algo() {
    local mode count
    if [ ! -e $MAPS/awfd_map ]; then                    # ipvs nginx haproxy: บันทึกแล้วโหลด mode ใหม่ด้วย algo นี้
        set_state algo "$*"
        local algo="$*"
        read -r mode count < $MODE_FILE
        load_mode $mode $count >/dev/null
        echo "algo: $mode $*"
        return
    fi
    stop_daemon
    flush_awfd_map
    set_state algo "$*"
    case $1 in
        ecmp) return ;;
        wcmp) set -- --static -m ${2:-4} ;;
        lcf)  set -- -m 1 -i ${2:-500} ;;
        awfd) set -- -m ${2:-4} -i ${3:-500} ;;
        *)    echo "algo: ecmp | wcmp [m] | lcf [interval_ms] | awfd [m] [interval_ms]"; exit 1 ;;
    esac
    setsid taskset -c $DAEMON_CPU "$REPO/xdp_lb_awfd" "$@" >/var/log/perf-awfd.log 2>&1 < /dev/null &
    echo $! > /run/perf-awfd.pid
    echo "daemon: xdp_lb_awfd $*"
}

set_feature() {
    [[ "$1" =~ ^(fragment|pmtu)$ && "$2" =~ ^(on|off)$ ]] || { echo "feature fragment|pmtu on|off"; exit 1; }
    "$REPO/xdp_lb_ctl" $1 $2
    set_state $1 $2
}

# สภาพก่อนยิงทุกรอบ: map ว่าง (โหลดใหม่), conntrack และ ipvs ว่าง, feature/algo เท่าเดิม
# พิมพ์ค่าที่ใช้จริงเป็น key=value  run_tests.sh เก็บลง .meta
# VIP และ route ไป backend ต้องอยู่บน LB_IFACE  systemd-networkd ลบทิ้งเมื่อถูก restart (เช่น unattended-upgrades)
#   แล้ว route ไป backend จะออกทางการ์ดของคณะ  ใส่กลับเมื่อหาย ถ้ายังไม่ออกทาง LB_IFACE ให้หยุดก่อนยิง
ensure_paths() {
    local i
    ip -o addr show dev $LB_IFACE | grep -q " $VIP/32 " || ip addr add $VIP/32 dev $LB_IFACE
    for i in $BACKENDS; do
        ip route replace $(backend_ip $i)/32 via $SERVER_IP dev $LB_IFACE
        ip route get $(backend_ip $i) | grep -q " dev $LB_IFACE " ||
            { echo "route ไป $(backend_ip $i) ไม่ออกทาง $LB_IFACE  หยุดก่อนยิง" >&2; exit 1; }
    done
}

reset() {
    local mode count fragment=off pmtu=off algo=ecmp
    ensure_paths
    if [ "${1:-}" = algo ]; then shift; set_state algo "$*"; fi
    read -r mode count < $MODE_FILE
    [ -f $STATE ] && source $STATE
    load_mode $mode $count >/dev/null
    if [ -e $MAPS/awfd_map ]; then
        [ $fragment = on ] && "$REPO/xdp_lb_ctl" fragment on >/dev/null
        [ $pmtu = on ] && "$REPO/xdp_lb_ctl" pmtu on >/dev/null
        set_algo $algo >/dev/null
        for map in conn_map frag_cache_map; do
            echo "b_${map}_max=$(bpftool -j map show pinned $MAPS/$map | jq .max_entries)"
        done
        echo "b_frag_timeout_s=$(sed -nE 's/.*define FRAG_TIMEOUT_NS \(([0-9]+)ULL.*/\1/p' "$REPO/xdp_lb_common.h")"
        echo "b_fragment=$fragment"
        echo "b_pmtu=$pmtu"
    fi
    echo "b_algo=$algo"
    conntrack -F 2>/dev/null || true
    echo "b_mode=$mode"
    echo "b_vips=$count"
    echo "b_bpf_stats=$(sysctl -n kernel.bpf_stats_enabled)"
    echo "b_conntrack=$(conntrack -C 2>/dev/null || echo 0)"
    echo "b_ipvs_conn=$(ipvsadm -Lnc 2>/dev/null | tail -n +3 | wc -l)"
}

up() {
    check_tools
    make -C "$REPO" xdp_lb.o xdp_lb_ctl xdp_lb_awfd >/dev/null
    tune_machine $LB_IFACE
    sysctl -qw net.ipv4.ip_forward=1
    for scope in all default $LB_IFACE; do
        sysctl -qw net.ipv4.conf.$scope.rp_filter=0
        sysctl -qw net.ipv4.conf.$scope.send_redirects=0
        sysctl -qw net.ipv4.conf.$scope.accept_redirects=0
    done
    systemctl stop nginx haproxy 2>/dev/null || true
    ensure_paths
    for i in $BACKENDS; do
        # bpf_fib_lookup ไม่ยิง ARP เอง neighbor ต้องมีก่อน
        ping -c 1 -W 1 $(backend_ip $i) >/dev/null || echo "ping $(backend_ip $i) ไม่ผ่าน  ตั้งเครื่อง C ก่อน"
    done
    set_mode xdp
}

snapshot() {
    host_snapshot $LB_IFACE
    if [ -e $PIN/prog ]; then
        bpftool -j prog show pinned $PIN/prog | jq -r '"xdp_run_cnt=\(.run_cnt // 0)", "xdp_run_time_ns=\(.run_time_ns // 0)"'
        "$REPO/xdp_lb_ctl" stats | awk '{print "stat_" $1 "=" $2}'
    fi
    echo "ct_count=$(conntrack -C 2>/dev/null || echo 0)"
}

# ข้อ 2: เวลาที่ฟังก์ชันประเมิน rule ใช้ต่อครั้ง จับด้วย fentry/fexit (kfunc/kretfunc ของ bpftrace)
#   nft = nft_do_chain ของ table perf_lb, ipt = ipt_do_table ของ table nat ที่ hook PREROUTING
#   mode อื่นไม่ต้องเริ่ม: xdp ใช้ bpf_stats ของทั้งโปรแกรมจาก snapshot
LOOKUP_LOG=/run/perf-lookup.txt
lookup_start() {
    local mode probe filter pid
    read -r mode _ < $MODE_FILE
    case $mode in
        nft) probe=nf_tables:nft_do_chain filter='str(((struct nft_chain *)args->priv)->table->name) == "perf_lb"' ;;
        ipt) probe=ip_tables:ipt_do_table
             filter='args->state->hook == 0 && ((struct xt_table *)args->priv)->name == "nat"' ;;
        *)   rm -f /run/perf-lookup.pid; return 0 ;;
    esac
    setsid stdbuf -oL bpftrace -e "kfunc:$probe /$filter/ { @start[cpu] = nsecs; }
kretfunc:$probe /@start[cpu]/ { @lookup_ns = sum(nsecs - @start[cpu]); @lookup_calls = count(); delete(@start[cpu]); }" \
        > $LOOKUP_LOG 2>&1 < /dev/null &
    pid=$!
    echo $pid > /run/perf-lookup.pid
    for _ in $(seq 100); do                             # ยิงหลัง probe ติดแล้วเท่านั้น
        grep -q '^Attaching' $LOOKUP_LOG && return 0
        kill -0 $pid 2>/dev/null || break
        sleep 0.1
    done
    cat $LOOKUP_LOG
    exit 1
}
lookup_stop() {
    local pid
    [ -f /run/perf-lookup.pid ] || return 0
    pid=$(cat /run/perf-lookup.pid)
    kill -INT $pid
    while kill -0 $pid 2>/dev/null; do sleep 0.05; done
    rm -f /run/perf-lookup.pid
    sed -nE 's/^@(lookup_[a-z]+): ([0-9]+)$/\1=\2/p' $LOOKUP_LOG
}

status() {
    echo "mode: $(cat $MODE_FILE 2>/dev/null || echo ไม่ได้ตั้ง)"
    cat $STATE 2>/dev/null || true
    ip -br addr show dev $LB_IFACE
    bpftool net show dev $LB_IFACE | grep -A1 '^xdp' || true
    if [ -f /run/perf-awfd.pid ] && kill -0 $(cat /run/perf-awfd.pid) 2>/dev/null; then
        echo "daemon: ทำงาน"
    else
        echo "daemon: หยุด"
    fi
    [ -e $PIN/prog ] && "$REPO/xdp_lb_ctl" stats || true
}

require_root
case "$1" in
    up)        up ;;
    down)      down_all; [ "${2:-}" = keep_vip ] || ip addr del $VIP/32 dev $LB_IFACE 2>/dev/null || true ;;
    mode)      set_mode "$2" "$3" ;;
    algo)      shift; set_algo "$@" ;;
    feature)   set_feature "$2" "$3" ;;
    reset)     shift; reset "$@" ;;
    bpf-stats) sysctl -qw kernel.bpf_stats_enabled=$([ "$2" = on ] && echo 1 || echo 0) ;;
    snapshot)  snapshot ;;
    cpu)       [[ "$2" =~ ^(start|stop)$ ]] || { echo "cpu start|stop"; exit 1; }
               cpu_$2 ;;
    lookup)    [[ "$2" =~ ^(start|stop)$ ]] || { echo "lookup start|stop"; exit 1; }
               lookup_$2 ;;
    env)      env_info $LB_IFACE; status ;;
    status)    status ;;
    *)         sed -n '2,19p' "$0"; exit 1 ;;
esac
