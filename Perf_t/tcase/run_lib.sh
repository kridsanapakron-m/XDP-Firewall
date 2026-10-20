#!/bin/bash
# ส่วนกลางของ tcase/<ข้อ>.sh: matrix, การสั่ง B/C, เครื่องมือยิง, ขั้นของหนึ่งรอบ, plan/eta, เริ่ม/จบการรัน
# ไม่ได้รันตรง ๆ  ไฟล์ข้อย่อย source ไฟล์นี้แล้วเรียก run_one <ข้อ> "$@"   รายละเอียดของแต่ละข้ออยู่ใน ../00_overview.txt
# ย้ายมาจาก ../run_tests.sh ด้วย logic เดิม  ต่างกันที่ run_case ถูกแยกเป็นขั้น (round_begin ... round_end)
# ให้ไฟล์ข้อย่อยเรียกเองตามลำดับ และคำสั่งที่เปลี่ยนสภาพเครื่องแสดงบนจอเป็น A$ / B$ / C$
#
# ===== ตั้งเครื่องครั้งแรก (ทำครั้งเดียวก่อนรันข้อไหนก็ได้) =====
# ด้วยสคริปต์ตามลำดับ:  C# ./setup_c_server.sh up   B# ./setup_b_lb.sh up   A# ./setup_a_client.sh up && ./setup_a_client.sh check
# ข้างล่างคือคำสั่งที่ให้ผลเท่ากัน ใช้ทำมือได้ (copy ไปวางบนเครื่องนั้นด้วย root)
#
# --- C (server): backend 3 ตัวใน netns + ตัวถอด IPIP + nginx/iperf ใน cgroup + agent ของ AWFD ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   make -C $REPO xdp_lb_deencap.o xdp_lb_agent
#   for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > $g; done
#   systemctl stop irqbalance
#   c=0; for irq in $(awk -v d=$SERVER_IFACE '$0 ~ d {sub(":", "", $1); print $1}' /proc/interrupts); do
#       echo $((c % QUEUES)) > /proc/irq/$irq/smp_affinity_list; c=$((c + 1)); done
#   sysctl -w net.ipv4.ip_forward=1
#   for s in all default $SERVER_IFACE; do
#       sysctl -w net.ipv4.conf.$s.rp_filter=0 net.ipv4.conf.$s.accept_redirects=0 net.ipv4.conf.$s.send_redirects=0; done
#   mkdir -p $WEBROOT
#   for f in 1k:1 10k:10 100k:100 1m:1024; do
#       dd if=/dev/urandom of=$WEBROOT/f${f%%:*} bs=1024 count=${f##*:} status=none; done
#   for i in 1 2 3; do
#       ip netns add server_$i
#       ip link add vh$i type veth peer name vn$i
#       ip link set vn$i netns server_$i
#       ip addr add $(backend_host_ip $i)/30 dev vh$i
#       ip link set vh$i up mtu 1600
#       sysctl -w net.ipv4.conf.vh$i.rp_filter=0
#       ip -n server_$i link set lo up
#       ip -n server_$i addr add $(backend_ip $i)/30 dev vn$i
#       ip -n server_$i link set vn$i up mtu 1600
#       ip -n server_$i route add default via $(backend_host_ip $i) dev vn$i
#       ip -n server_$i addr add $VIP/32 dev lo
#       ip -n server_$i route add local 10.100.0.0/16 dev lo
#       ip netns exec server_$i sysctl -w net.ipv4.conf.all.rp_filter=0 \
#           net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.all.arp_announce=2
#       ip -n server_$i link set dev vn$i xdpgeneric obj $REPO/xdp_lb_deencap.o sec xdp
#       ip netns exec server_$i nft -f - <<NFT
#   table inet perf_sink {
#       counter udp_in {}
#       counter udp_frag_in {}
#       chain input {
#           type filter hook input priority 0; policy accept;
#           udp dport $VPORT counter name udp_in drop
#           ip saddr $CLIENT_IP udp dport $VPORT_FRAG counter name udp_frag_in drop
#           udp dport $VPORT_FRAG drop
#       }
#   }
#   NFT
#       mkdir -p /tmp/perf-nginx-$i
#       cat > /etc/nginx/perf-backend-$i.conf <<NGINX
#   worker_processes 1;
#   worker_rlimit_nofile 65536;
#   pid /run/perf-nginx-$i.pid;
#   error_log /var/log/perf-nginx-$i.err warn;
#   events { worker_connections 8192; }
#   http {
#       access_log off;
#       sendfile on;
#       keepalive_requests $KEEPALIVE_REQS;
#       default_type application/octet-stream;
#       client_body_temp_path /tmp/perf-nginx-$i/body;
#       proxy_temp_path       /tmp/perf-nginx-$i/proxy;
#       fastcgi_temp_path     /tmp/perf-nginx-$i/fastcgi;
#       uwsgi_temp_path       /tmp/perf-nginx-$i/uwsgi;
#       scgi_temp_path        /tmp/perf-nginx-$i/scgi;
#       server {
#           listen $VIP:$VPORT backlog=8192 reuseport;
#           listen $(backend_ip $i):$VPORT backlog=8192 reuseport;
#           root $WEBROOT;
#           location = /id { return 200 "backend-$i\n"; }
#           location = /nginx_status { stub_status; allow $(backend_ip $i); deny all; }
#       }
#   }
#   NGINX
#       systemd-run --quiet --scope --unit backend$i -p AllowedCPUs=$(backend_cpus $i) \
#           -p CPUQuota=100% -p CPUQuotaPeriodSec=10ms sh -c "ip netns exec server_$i nginx -c /etc/nginx/perf-backend-$i.conf &&
#               ip netns exec server_$i iperf -s -p $IPERF_PORT -D" < /dev/null >> /var/log/perf-backend-$i.log 2>&1
#       setsid taskset -c $AGENT_CPU nsenter --net=/var/run/netns/server_$i -- \
#           $REPO/xdp_lb_agent $(backend_ip $i) /sys/fs/cgroup/system.slice/backend$i.scope \
#           > /var/log/perf-agent-$i.log 2>&1 < /dev/null &
#   done
#   (แล้วตั้ง mode ของ C เป็น guarded ตามบล็อก "C: mode" ในไฟล์ข้อย่อย)
#
# --- B (LB) ---
#   source /root/XDP-Firewall/Perf_t/perf_env.sh
#   make -C $REPO xdp_lb.o xdp_lb_ctl xdp_lb_awfd
#   for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > $g; done
#   systemctl stop irqbalance nginx haproxy
#   c=0; for irq in $(awk -v d=$LB_IFACE '$0 ~ d {sub(":", "", $1); print $1}' /proc/interrupts); do
#       echo $((c % QUEUES)) > /proc/irq/$irq/smp_affinity_list; c=$((c + 1)); done
#   (TUNE_NIC=1 เท่านั้น ห้ามรันกับ X540 ของ B บน lab เพราะหลุดจาก PCIe:
#    ethtool -L $LB_IFACE combined $QUEUES; ethtool -N $LB_IFACE rx-flow-hash udp4 sdfn; ethtool -N $LB_IFACE rx-flow-hash tcp4 sdfn)
#   sysctl -w net.ipv4.ip_forward=1
#   for s in all default $LB_IFACE; do
#       sysctl -w net.ipv4.conf.$s.rp_filter=0 net.ipv4.conf.$s.send_redirects=0 net.ipv4.conf.$s.accept_redirects=0; done
#   ip addr add $VIP/32 dev $LB_IFACE
#   for i in 1 2 3; do ip route replace $(backend_ip $i)/32 via $SERVER_IP dev $LB_IFACE; ping -c 1 -W 1 $(backend_ip $i); done
#   (แล้วตั้ง mode xdp ตามบล็อก "B: mode xdp" ในไฟล์ข้อย่อย)
#
# --- A (client) ---
#   source <repo บน A>/Perf_t/perf_env.sh
#   modprobe pktgen
#   for s in all default $CLIENT_IFACE; do sysctl -w net.ipv4.conf.$s.rp_filter=0 net.ipv4.conf.$s.accept_redirects=0; done
#   ip route replace $VIP/32 dev $CLIENT_IFACE mtu lock $VIP_MTU
#   ip route replace 192.168.200.0/22 via $SERVER_IP dev $CLIENT_IFACE mtu lock $VIP_MTU
#   curl -s http://$VIP:$VPORT/id                      # ตรวจว่า VIP ตอบ (ได้ backend-1..3 สลับกัน)
#
# shellcheck disable=SC2086,SC2046,SC2206,SC2029,SC2034   # แยกคำโดยตั้งใจ, ตัวแปรใช้ในไฟล์ข้อย่อย
set -e

TCASE_DIR=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
SCRIPT_DIR=$(dirname "$TCASE_DIR")                  # Perf_t: perf_env.sh, report.py, results/
# shellcheck source=../perf_env.sh
source "$SCRIPT_DIR/perf_env.sh"
# ผลของชุดการทดลอง: results/<CAMPAIGN>/<ข้อ>/  ตั้ง RUN_DIR เอง = ใช้โฟลเดอร์นั้นแทน
CAMPAIGN=${CAMPAIGN:-20261018}
RESULTS=$SCRIPT_DIR/results/$CAMPAIGN
USER_RUN_DIR=${RUN_DIR:-}
RUN_DIR=${RUN_DIR:-$RESULTS}

# --- matrix กลาง (ตัวเลขตรงกับ 00_overview.txt หัวข้อ 7) ---
DURATION=${DURATION:-20}                  # วินาทีต่อรอบของ UDP
HTTP_DURATION=${HTTP_DURATION:-40}        # วินาทีต่อรอบของ HTTP และ iperf (wrk2 ใช้ ~10 s แรกปรับเทียบ)
HTTP_DURATION_DYNAMIC=${HTTP_DURATION_DYNAMIC:-60}  # 4.4: ต้องมีเวลาหลังเปลี่ยน quota
IDLE_DURATION=${IDLE_DURATION:-10}        # รอบ idle (ไม่มี traffic) ของข้อ 1 และ 3
REPS_UDP=${REPS_UDP:-${REPS:-10}}         # ข้อ 1.1  ชุดใหม่ใช้ 10 rep ทุกข้อ
REPS_TEST2=${REPS_TEST2:-${REPS:-10}}
REPS_TEST3=${REPS_TEST3:-${REPS:-10}}
REPS_HTTP=${REPS_HTTP:-${REPS:-10}}
SETTLE=${SETTLE:-1}                       # วินาทีหลัง reset ก่อนยิง
RESUME=${RESUME:-1}                       # 1 = ข้ามรอบที่เสร็จแล้ว (มี t_end_ns ไม่มี traffic_error/invalid)
OVERHEAD=${OVERHEAD:-}                    # วินาทีที่เสียต่อรอบของ plan  ว่าง = ค่าเฉลี่ยที่วัดได้ใน RUN_DIR หรือ 5
PPS_LADDER=${PPS_LADDER:-"50000 100000 250000 500000 1000000"}  # frame 64 B  ต่ำกว่าขาออกหลังห่อ IPIP (~1.20 Mpps)
SIZES=${SIZES:-"64 512 1024 1400"}        # ขนาด frame (รวม FCS)
SIZE_SWEEP_PPS=${SIZE_SWEEP_PPS:-50000}   # ระดับเดียวที่ทุกขนาดทำได้แม้ห่อ IPIP
STRESS_PPS=${STRESS_PPS:-}                # เช่น 1200000  ติดป้าย link_bound=1  (ปิดไว้)
PKTGEN_THREADS=${PKTGEN_THREADS:-2}
SRC_PER_THREAD=125                        # thread t ใช้ source FLOW_SRC_BASE + 125t .. +124
EST_PORTS=${EST_PORTS:-4}                 # EST: 125 IP x 4 port = 500 tuple ต่อ thread (2 thread = 1,000)
NEW_PORTS=${NEW_PORTS:-64511}             # NEW: 125 x 64,511 (coprime) = 8.06M ต่อ thread  ไม่วนซ้ำในรอบ
CONNS=${CONNS:-128}
HTTP_THREADS=${HTTP_THREADS:-4}
SAT_RATE=${SAT_RATE:-2000000}             # -R ของ wrk2 ตอน sat: สูงเกินจริงจนเป็น closed-loop
STREAMS=${STREAMS:-16}                    # stream ของ iperf
WEB_FILES=${WEB_FILES:-"1k 10k 100k 1m mix"}  # web-mix = 1k 70%, 10k 20%, 100k 9%, 1m 1%
HTTP_TOOL=${HTTP_TOOL:-$(command -v wrk2 >/dev/null && echo wrk2 || echo h2load)}
RAW_TOOL=${RAW_TOOL:-hping3}              # ข้อ 3.3 3.4: hping3 หรือ tcpreplay (pcap ที่สร้างไว้ก่อน)

# --- ค่าของแต่ละข้อ ---
TEST1_MODES=${TEST1_MODES:-"xdp ipvs nft ipt nginx haproxy"}
TEST12_LEVELS=${TEST12_LEVELS:-75}        # ข้อ 1.2 % ของ C0 (+ sat)  CPU ต่อ request แทบไม่เปลี่ยนตาม load
LAT_RATE=${LAT_RATE:-1000}                # ข้อ 1.4 req/s รวม
VIP_COUNTS=${VIP_COUNTS:-"1 10 100 1000"} # 10000 ต้องขยาย MAX_VIPS ก่อน
TEST2_PPS=${TEST2_PPS:-40000}             # NEW ไม่เกิน conntrack max (40k x 20 s = 800k)
TEST3_PPS=${TEST3_PPS:-"500000 100000"}
FRAG_TOTAL_PPS=${FRAG_TOTAL_PPS:-100000}  # ข้อ 3.3 อัตรารวม (packet/s)
FRAG_PERCENTS=${FRAG_PERCENTS:-"10 20 50 70 90"}  # ระดับ 0% คือ 3.2 ที่ 100k EST
PMTU_PPS=${PMTU_PPS:-50000}
FLOOD_RATE=${FLOOD_RATE:-100000}          # ข้อ 3.5 datagram/s source สุ่ม
FRAG_FLOW_RATE=${FRAG_FLOW_RATE:-1000}    # ข้อ 3.5 datagram/s ของ flow ปกติ
# ข้อ 4: <LB>:<อัลกอริทึม>  least-connection ของ LB อื่นใส่น้ำหนัก = quota ตอนเริ่มรอบ
#   รันหนึ่งครั้งต้องเป็น xdp ทั้งหมดหรือ LB อื่นทั้งหมด (สลับมี/ไม่มี XDP ทำให้การ์ดของ B reset ทุก rep)
TEST4_VARIANTS=${TEST4_VARIANTS:-"xdp:ecmp xdp:wcmp xdp:awfd4"}  # LB อื่น: ipvs:rr ipvs:wlc nft:rr ipt:rr nginx:least_conn haproxy:leastconn
TEST4_LEVELS=${TEST4_LEVELS:-${LOAD_LEVELS:-"50 75 90"}}  # ข้อ 4: % ของ C0 แบบ open-loop
TEST4_SAT_REPS=${TEST4_SAT_REPS:-1}       # sat ของข้อ 4 แยกออกมา รอบต่อคู่ (algo, ไฟล์) ไว้เช็ค Ω < 0.9
declare -A QUOTA=(                        # CPUQuota ของ backend 1 2 3  (100% = 1 core)
    [equal]=${QUOTA_EQUAL:-"100% 100% 100%"}            # ข้อ 0.1 1 3
    [unequal]=${QUOTA_UNEQUAL:-"100% 50% 25%"}          # ข้อ 5
    # ข้อ 4: CPU รวม 0.9 core ทุกแบบ  web-1k ได้ ~52k req/s (~540 Mbit/s) backend จึงตันก่อนสาย 1G
    [balanced]=${QUOTA_BALANCED:-"30% 30% 30%"}
    [skewed]=${QUOTA_SKEWED:-"60% 20% 10%"}
    [oneslow]=${QUOTA_ONESLOW:-"40% 40% 10%"}
    [dynamic_after]=${QUOTA_DYNAMIC_AFTER:-"30% 30% 10%"}   # ข้อ 4.4: เริ่ม balanced แล้วเปลี่ยนที่ 1/3 ของรอบ
)
TEST4_SCENARIOS="balanced skewed oneslow dynamic_after"   # C0 ของข้อ 4 (ข้อ 0.3)

PLAN=""                                   # ไม่ว่าง = นับรอบอย่างเดียว ไม่ยิงจริง (plan และเวลาที่คาดว่าจะเสร็จ)
LAST_END_NS=""                            # t_end ของรอบก่อน ใช้คิดเวลาเสียต่อรอบ (gap_ms)
declare -A RAN=()                         # รอบที่ผ่าน run_case แล้วในการรันครั้งนี้

# ssh ครั้งแรกเปิด connection ค้างไว้ 10 นาที ครั้งต่อไปใช้ซ้ำ (ไม่ต้อง handshake ทุกคำสั่ง)
ssh_options="-o BatchMode=yes -o ConnectTimeout=5 -o ControlMaster=auto -o ControlPersist=10m"

# shellcheck source=cmd.sh
source "$TCASE_DIR/cmd.sh"                          # cmd field delta ratio  (ใช้ ssh_options ข้างบน)

# --- สั่งเครื่อง: คำสั่งที่เปลี่ยนสภาพเครื่องแสดงบนจอเป็น A$ B$ C$ และต่อท้าย env-a.txt (ยกเว้นที่ทำทุกรอบ) ---
# setup_log <เครื่อง> <คำสั่งย่อย> <คำสั่งเต็ม>
setup_log() {
    case $2 in snapshot|cpu|status|env) return 0 ;; esac
    echo "  $1\$ $3" >&2
    case $2 in reset|lookup|sample) ;; *) echo "$(date '+%F %T') $1\$ $3" >> "$RUN_DIR/env-a.txt" ;; esac
}
on_b() { if [ -z "$PLAN" ]; then setup_log B $1 "setup_b_lb.sh $*"; ssh $ssh_options $SSH_LB "$PERF_DIR/setup_b_lb.sh $*"; fi; }
on_c() { if [ -z "$PLAN" ]; then setup_log C $1 "setup_c_server.sh $*"; ssh $ssh_options $SSH_SERVER "$PERF_DIR/setup_c_server.sh $*"; fi; }
vip_route() {
    if [ -z "$PLAN" ]; then
        setup_log A route "ip route replace $VIP/32 dev $CLIENT_IFACE $*"
        ip route replace $VIP/32 dev $CLIENT_IFACE "$@"
    fi
}
note() { echo "$*" >&2; if [ -z "$PLAN" ]; then echo "$*" >> "$RUN_DIR/env-a.txt"; fi; }   # การตัดสินใจอัตโนมัติ
c_mode_for() { case $1 in nft|ipt) echo nat ;; *) echo guarded ;; esac; }
gcd() { if (( $2 )); then gcd $2 $(( $1 % $2 )); else echo $1; fi; }
lcm() { echo $(( $1 * $2 / $(gcd $1 $2) )); }
share() { echo $(( $1 * $2 / 3 - $1 * ($2 - 1) / 3 )); }    # ส่วนที่ $2 (1..3) ของ $1 รวม 3 ส่วนได้ $1 พอดี
pgset() { echo "pgset $1: $2"; echo "$2" > /proc/net/pktgen/$1; }
show() { echo "# $*"; "$@"; }

# --- pktgen: ตั้งผ่าน /proc/net/pktgen  ทุกบรรทัดที่ตั้งถูกพิมพ์ลงผลด้วย ---

# pktgen dst_mac=.. dst=.. [dst_count=N] size=.. pps=.. seconds=.. [ports=..] [dsts="ip ip ip"]
#   ไม่ตั้ง flag RND: src IP, src port และ dst ไล่ทีละหนึ่งพร้อมกันทุก packet  tuple วนที่ lcm(125, ports, dst_count)
#   thread t ใช้ source คนละช่วง (FLOW_SRC_BASE + 125t)  dsts = thread t ยิงไป ip ตัวที่ t+1 (ข้อ 3.0)
pktgen() {
    local dst_mac dst dst_count=1 size pps seconds ports=$EST_PORTS dsts
    local "$@"
    local threads=$PKTGEN_THREADS sent=0 achieved=0 thread device source target count rate
    [ -n "$dsts" ] && threads=$(wc -w <<< "$dsts")
    for device in /proc/net/pktgen/kpktgend_*; do pgset ${device##*/} "rem_device_all" >/dev/null; done
    for ((thread = 0; thread < threads; thread++)); do
        device=$CLIENT_IFACE@$thread
        source=$(ip_add $FLOW_SRC_BASE $(( thread * SRC_PER_THREAD )))
        target=${dst:-$(cut -d' ' -f$(( thread + 1 )) <<< "$dsts")}
        pgset kpktgend_$thread "add_device $device"
        pgset $device "count $(( pps * seconds / threads ))"
        pgset $device "clone_skb 0"
        pgset $device "pkt_size $(( size - 4 ))"
        pgset $device "ratep $(( pps / threads ))"
        pgset $device "dst_mac $dst_mac"
        pgset $device "dst_min $target"
        pgset $device "dst_max $(ip_add $target $(( dst_count - 1 )))"
        pgset $device "src_min $source"
        pgset $device "src_max $(ip_add $source $(( SRC_PER_THREAD - 1 )))"
        pgset $device "udp_dst_min $VPORT"
        pgset $device "udp_dst_max $VPORT"
        pgset $device "udp_src_min 1024"
        pgset $device "udp_src_max $(( 1024 + ports ))"         # max ไม่นับ: port 1024 .. 1024+ports-1
        pgset $device "queue_map_min $thread"
        pgset $device "queue_map_max $thread"
    done
    pgset pgctrl "start"
    for ((thread = 0; thread < threads; thread++)); do
        device=/proc/net/pktgen/$CLIENT_IFACE@$thread
        grep -A1 '^Result:' $device || true
        count=$(awk '/pkts-sofar/ {print $2}' $device)
        rate=$(awk '/^Result: OK/ {getline; print $1 + 0}' $device)
        sent=$(( sent + ${count:-0} )) achieved=$(( achieved + ${rate:-0} ))
    done
    echo "traffic: tool=pktgen kind=whole sent=$sent target_pps=$pps achieved_pps=$achieved" \
         "tuples=$(( threads * $(lcm $(lcm $SRC_PER_THREAD $ports) $dst_count) ))"
}

# --- hping3 และ tcpreplay: fragment และ DF  (pktgen ตั้ง DF และแบ่ง fragment ไม่ได้) ---

# hping <kind> <datagram/s> <วินาที> <arg ของ hping3...>
#   hping3 ไม่มี duration จึงหยุดด้วย SIGINT แล้วอ่านจำนวนที่ส่งจากสรุปท้าย ("packets tramitted")
#   hping3 คืนค่า 1 เมื่อไม่มีตอบกลับ (UDP ถูกทิ้งที่ backend) จึงไม่ใช้ exit code
hping() {
    local kind=$1 rate=$2 seconds=$3 start output sent
    shift 3
    start=$(date +%s%N)
    # -k 5: hping3 ที่พักสั้นมากบางครั้งไม่หยุดเมื่อได้ SIGINT  kill ตามไปไม่ให้ยิงค้าง
    output=$(show timeout -s INT -k 5 $seconds hping3 -q -i u$(( 1000000 / rate )) "$@" 2>&1) || true
    echo "$output"
    sent=$(awk '/packets tra[a-z]*itted/ {print $1}' <<< "$output")
    [ -n "$sent" ] || return 1
    echo "traffic: tool=hping3 kind=$kind sent=$sent target_pps=$rate" \
         "achieved_pps=$(( sent * 1000000000 / ($(date +%s%N) - start) ))"
}

# replay <kind> <datagram/s> <วินาที> <pcap> <packet ต่อ datagram>
replay() {
    local kind=$1 rate=$2 output
    output=$(show tcpreplay -i $CLIENT_IFACE --pps=$(( rate * $5 )) --duration=$3 --loop=0 $4 2>&1) || true
    echo "$output"
    grep -q '^Actual: [0-9]* packets' <<< "$output" || return 1
    awk -v kind=$kind -v rate=$rate -v per=$5 '/^Actual: [0-9]+ packets/ {
        printf "traffic: tool=tcpreplay kind=%s sent=%d target_pps=%d achieved_pps=%d\n",
               kind, $2 / per, rate, $2 / per / $(NF - 1) }' <<< "$output"
}

# pcap ของ tcpreplay: frag = datagram 908 B ไป VPORT_FRAG แบ่ง 2 fragment (504 + 404)
#                     df<ขนาด IP> = UDP ไป VPORT ตั้ง DF   ทุกแบบมี 8192 datagram (IP ID และ sport ต่างกัน)
pcap_of() {
    local file=$RUN_DIR/$1.pcap
    [ -f $file ] || python3 - $file $1 $(cat /sys/class/net/$CLIENT_IFACE/address) $LB_MAC \
        $CLIENT_IP $VIP $VPORT $VPORT_FRAG <<'PY'
import socket, struct, sys
path, kind, src_mac, dst_mac, src, dst, vport, frag_port = sys.argv[1:]
ethernet = bytes.fromhex(dst_mac.replace(":", "") + src_mac.replace(":", "")) + b"\x08\x00"

def packet(ident, flags_offset, payload):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, flags_offset, 64, 17, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    total = sum(struct.unpack("!10H", header))
    checksum = ~((total & 0xffff) + (total >> 16)) & 0xffff
    return ethernet + header[:10] + struct.pack("!H", checksum) + header[12:] + payload

packets = []
for ident in range(8192):
    if kind == "frag":
        datagram = struct.pack("!HHHH", 1024 + ident, int(frag_port), 908, 0) + bytes(900)
        packets += [packet(ident, 0x2000, datagram[:504]), packet(ident, 504 // 8, datagram[504:])]
    else:
        size = int(kind[2:])
        packets.append(packet(ident, 0x4000, struct.pack("!HHHH", 1024 + ident, int(vport), size - 20, 0)
                              + bytes(size - 28)))
with open(path, "wb") as out:
    out.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for data in packets:
        out.write(struct.pack("<IIII", 0, 0, len(data), len(data)) + data)
PY
    echo $file
}

# raw <frag|df1470|df1490> <datagram/s> <วินาที>  ด้วย RAW_TOOL
raw() {
    if [ $RAW_TOOL = tcpreplay ]; then
        replay $1 $2 $3 $(pcap_of $1) $([ $1 = frag ] && echo 2 || echo 1)
    elif [ $1 = frag ]; then
        hping frag $2 $3 --udp -p $VPORT_FRAG -d 900 -m 504 $VIP
    else
        hping $1 $2 $3 --udp -p $VPORT -y -d $(( ${1#df} - 28 )) $VIP
    fi
}

# --- HTTP และ TCP stream ---

# web-mix ของ wrk2: 100 path  1 KB 70, 10 KB 20, 100 KB 9, 1 MB 1  สลับลำดับคงที่ (seed 1)
mix_lua() {
    local file=$RUN_DIR/mix.lua
    [ -f $file ] || cat > $file <<'LUA'
local paths = {}
for _, entry in ipairs({{"/f1k", 70}, {"/f10k", 20}, {"/f100k", 9}, {"/f1m", 1}}) do
    for _ = 1, entry[2] do paths[#paths + 1] = entry[1] end
end
math.randomseed(1)
for i = #paths, 2, -1 do
    local j = math.random(i)
    paths[i], paths[j] = paths[j], paths[i]
end
local n = 0
request = function()
    n = n % #paths + 1
    return wrk.format(nil, paths[n])
end
LUA
    echo $file
}

# web-mix ของ h2load: รายการ URI 100 บรรทัด สัดส่วนเดียวกัน
uri_file() {
    local file=$RUN_DIR/uris-$1.txt entry n
    if [ ! -f $file ]; then
        for entry in f1k:70 f10k:20 f100k:9 f1m:1; do
            for ((n = 0; n < ${entry##*:}; n++)); do echo "http://$1:$VPORT/${entry%%:*}"; done
        done | shuf --random-source=<(yes) > $file
    fi
    echo $file
}

# HTTP มาตรฐาน: http <host> <ไฟล์> <req/s รวม | sat> <connection> [close]
#   wrk2 -R = อัตรารวมทุก connection (open-loop, latency แก้ coordinated omission แล้ว)  sat = -R สูงมาก
#   ไม่มี wrk2: h2load --rps (ต่อ client) และ --log-file ให้ report.py คำนวณ percentile เอง
#   close = "Connection: close" ทุก request  ทั้งสองตัวต่อ connection ใหม่เองเมื่อ server ปิด
http() {
    local host=$1 file=$2 rate=$3 conns=$4 close=${5:+-H Connection:close}
    local threads=$(( conns < HTTP_THREADS ? conns : HTTP_THREADS )) url=http://$1:$VPORT/f${2/mix/1k}
    if [ $HTTP_TOOL = wrk2 ]; then
        [ $rate = sat ] && rate=$SAT_RATE
        show wrk2 -t $threads -c $conns -d ${HTTP_DURATION}s -R $rate --latency $close \
            $([ $file = mix ] && echo -s $(mix_lua)) $url
    else
        show h2load --h1 -t $threads -c $conns -D $HTTP_DURATION --warm-up-time 2 $close \
            $([ $rate = sat ] || awk -v r=$rate -v c=$conns 'BEGIN {printf "--rps %.4f", r / c}') \
            --log-file "$out.lat$part" $([ $file = mix ] && echo -i $(uri_file $host) || echo $url)
    fi
}

web_file() { local file=${1#web-}; echo ${file%-close}; }
close_of() { if [[ $1 == *-close ]]; then echo close; fi; }
web_loads() { local file; for file in ${1:-$WEB_FILES}; do echo web-$file; done; }

# workload ไปที่ VIP: via_vip <workload> <req/s | sat>
via_vip() {
    if [ $1 = elephant ]; then
        show iperf -c $VIP -p $IPERF_PORT -P $STREAMS -t $HTTP_DURATION -f m
    else
        http $VIP $(web_file $1) $2 $CONNS $(close_of $1)
    fi
}

# ยิงตรงไป backend 3 ตัวพร้อมกัน ชุดละ backend (ข้อ 0, 1.4)  แบ่ง connection/stream/rate ให้รวมเท่ากับชุดเดียว
#   direct3 <workload> <req/s รวม | sat>   ผลของแต่ละชุดขึ้นต้นด้วย "## backend i"
direct3() {
    local load=$1 rate=$2 i part pids=() failed=0 HTTP_THREADS=$(( (HTTP_THREADS + 2) / 3 ))
    for i in $BACKENDS; do
        part=.b$i
        {
            echo "## backend $i"
            if [ $load = elephant ]; then
                show iperf -c $(backend_ip $i) -p $IPERF_PORT -P $(share $STREAMS $i) -t $HTTP_DURATION -f m
            else
                http $(backend_ip $i) $(web_file $load) $(if [ $rate = sat ]; then echo sat; else share $rate $i; fi) \
                    $(share $CONNS $i) $(close_of $load)
            fi
        } > "$out.part$i" 2>&1 &
        pids+=($!)
    done
    for i in "${pids[@]}"; do wait $i || failed=1; done
    cat "$out".part*
    rm -f "$out".part*
    return $failed
}

# ข้อ 2: bpftrace บน B จับเวลาหา rule เฉพาะช่วงยิง  ผลลง <id>.lookup
traced() {
    local status=0
    on_b lookup start || return 1
    "$@" || status=$?
    on_b lookup stop > "$out.lookup"
    return $status
}

# ข้อ 4.4: sampler บน C ทุก 1 วินาที (<id>.ts) และเปลี่ยน quota ที่ 1/3 ของรอบ  เวลาเปลี่ยนจริงลง .meta
dynamic() {
    local sampler changer status=0
    on_c sample $HTTP_DURATION > "$out.ts" &
    sampler=$!
    ( sleep $(( HTTP_DURATION / 3 )); on_c quota ${QUOTA[dynamic_after]} | grep quota_ns >> "$out.meta" ) &
    changer=$!
    "$@" || status=$?
    wait $sampler $changer || true
    return $status
}

# --- การวัดหนึ่งรอบ ---

snapshot_all() {
    local a b
    host_snapshot $CLIENT_IFACE > "$1.a$2" &
    a=$!
    on_b snapshot > "$1.b$2" &
    b=$!
    on_c snapshot > "$1.c$2"
    wait $a $b
}

# mpstat ของ A B C พร้อมกัน: start หลังตัวนับก่อนยิง  stop ก่อนตัวนับหลังยิง เก็บเป็น <out>.cpu-{a,b,c}.json.gz
cpu_all() {
    local a b
    if [ $1 = start ]; then
        cpu_start
        on_b cpu start &
        b=$!
        on_c cpu start
        wait $b
    else
        cpu_stop | gzip > "$2.cpu-a.json.gz" &
        a=$!
        on_b cpu stop | gzip > "$2.cpu-b.json.gz" &
        b=$!
        on_c cpu stop | gzip > "$2.cpu-c.json.gz"
        wait $a $b
    fi
}

# อัตราที่ยิงได้จริงต่ำกว่า 95% ของเป้า -> invalid=rate  (flood ของ 3.5 ยิงเท่าที่ได้ ไม่ตรวจ)
check_rate() {
    awk '/^traffic:/ { for (f = 2; f <= NF; f++) { split($f, kv, "="); v[kv[1]] = kv[2] }
                       if (v["kind"] != "flood" && v["achieved_pps"] + 0 < 0.95 * v["target_pps"]) bad = 1 }
         END { if (bad) print "invalid=rate" }' "$1.client" >> "$1.meta"
}

# รอบที่เสร็จแล้ว: มี t_end_ns และไม่มี traffic_error / invalid
round_done() { [ -f "$1.meta" ] && grep -q '^t_end_ns=' "$1.meta" && ! grep -q '^traffic_error=\|^invalid=' "$1.meta"; }

# โหมด plan: นับรอบและเวลา (วินาทีที่ยิง + เวลาเสียต่อรอบ)  รอบที่เสร็จแล้วไม่นับใน "ยังไม่เสร็จ"
plan_count() {
    local out=$1 seconds=$2
    PLAN_ROUNDS=$(( PLAN_ROUNDS + 1 )) PLAN_MS=$(( PLAN_MS + seconds * 1000 + OVERHEAD_MS ))
    if [ "$RESUME" != 1 ] || ! round_done "$out"; then
        PLAN_LEFT=$(( PLAN_LEFT + 1 )) PLAN_LEFT_MS=$(( PLAN_LEFT_MS + seconds * 1000 + OVERHEAD_MS ))
    fi
}

# --- ขั้นของหนึ่งรอบ: ไฟล์ข้อย่อยเรียกตามลำดับ  ไฟล์ผล <id>-r<rep>.*  ($rep มาจากลูปของข้อย่อย) ---

# round_begin <id> <วินาทีที่ยิง> "<key=value ...>"  ตั้ง id และ out ของรอบ แล้วเขียน .meta
#   คืน 1 = ไม่ต้องยิง: รอบซ้ำในการรันครั้งนี้ (control ของข้อ 5), โหมด plan (นับอย่างเดียว), RESUME และเสร็จแล้ว
round_begin() {
    id=$1 out=$RUN_DIR/$1-r$rep
    if [ -n "${RAN[$out]:-}" ]; then return 1; fi
    RAN[$out]=1
    if [ -n "$PLAN" ]; then plan_count "$out" $2; return 1; fi
    if [ "$RESUME" = 1 ] && round_done "$out"; then echo "  $id r$rep    ข้าม (เสร็จแล้ว)"; return 1; fi
    SEQ=$(( SEQ + 1 ))
    tr ' ' '\n' <<< "case=$id rep=$rep seq=$SEQ $3" > "$out.meta"
    echo "  $id r$rep"
}

# reset B: โหลด mode เดิมใหม่ (map ว่าง) + feature/algo เดิม + ล้าง conntrack/ipvs  ค่าที่ตั้งจริงลง .meta  แล้วรอ SETTLE
#   RESET_ARGS เช่น "algo awfd 4 500" = บันทึก algo ใหม่ก่อน daemon จึงเริ่มครั้งเดียวตอน reset
#   B_OFF_PATH=1: B ไม่อยู่ในเส้นทาง (0.x, 3.0, direct ของ 1.4) ไม่แตะ B เลย  ไม่สลับ XDP การ์ดของ B จึงไม่ reset
reset_b() {
    if [ -n "${B_OFF_PATH:-}" ]; then echo "b_mode=none" >> "$out.meta"; else on_b reset ${RESET_ARGS:-} >> "$out.meta"; fi
    sleep $SETTLE
}

# ตัวนับของ A B C พร้อมกัน (NIC, ต่อคิว, bpf_stats, xdp_lb_ctl stats, backend)  0 = ก่อนยิง 1 = หลังยิง  report.py อ่าน
read_counters() { snapshot_all "$out" $1; }

# mpstat -P ALL 1 บน A B C  เริ่มหลังตัวนับก่อนยิง หยุดก่อนตัวนับหลังยิง  -> <id>.cpu-{a,b,c}.json.gz
cpu_begin() { cpu_all start; }
cpu_end() { cpu_all stop "$out"; }

# บรรทัดสรุปที่เครื่องมือพิมพ์เองตอนจบ (แสดงบนจอ)  ผลเต็มอยู่ใน <id>.client
TRAFFIC_SUMMARY='^# (wrk2|h2load|iperf|timeout|tcpreplay) |^## backend|^Result:|pps .*errors|packets tra[a-z]*itted|'
TRAFFIC_SUMMARY+='requests in|^Requests/sec|^Transfer/sec|Socket errors|Non-2xx|^ +(50|90|99)\.000%|^ +99\.900%|'
TRAFFIC_SUMMARY+='\[SUM\]|^Actual:|^finished in|^requests:|^time for request:|^traffic:'

# traffic <คำสั่ง...>: ยิงแล้วเก็บผลลง <id>.client  เวลาเริ่ม/จบ และ gap_ms (เวลาเสียตั้งแต่จบรอบก่อน) ลง .meta
traffic() {
    local start
    echo "  A\$ $*"
    echo "# command: $*" > "$out.client"
    start=$(date +%s%N)
    echo "t_start_ns=$start" >> "$out.meta"
    if [ -n "$LAST_END_NS" ]; then echo "gap_ms=$(( (start - LAST_END_NS) / 1000000 ))" >> "$out.meta"; fi
    "$@" >> "$out.client" 2>&1 || echo "traffic_error=1" >> "$out.meta"
    LAST_END_NS=$(date +%s%N)
    echo "t_end_ns=$LAST_END_NS" >> "$out.meta"
    grep -E "$TRAFFIC_SUMMARY" "$out.client" | sed 's/^/     /' || true
}

# ตรวจ rate (ต่ำกว่า 95% ของเป้า = invalid=rate ไม่เอาไปเฉลี่ย) และบีบไฟล์ latency ของ h2load
round_end() {
    check_rate "$out"
    if compgen -G "$out.lat*" >/dev/null; then gzip -f "$out".lat*; fi
    if grep -q '^traffic_error=\|^invalid=' "$out.meta"; then echo "     $(grep '^traffic_error=\|^invalid=' "$out.meta" | tr '\n' ' ')"; fi
}

# show_cpu <a|b|c>: core เฉลี่ยรายวินาทีจาก mpstat ของรอบนี้ (100 − %idle − %iowait  สูตรเดียวกับ report.py)
#   มีรอบ idle ของ mode นี้ใน rep เดียวกัน (IDLE_OUT จาก idle_round) ก็แสดงคู่กัน
show_cpu() {
    local idle=""
    if [ -n "${IDLE_OUT:-}" ] && [ "$IDLE_OUT" != "$out" ]; then idle="idle $(mpstat_cores "$IDLE_OUT.cpu-$1.json.gz") core   "; fi
    echo "  CPU ของ ${1^^} (mpstat)        ${idle}ระหว่างยิง $(mpstat_cores "$out.cpu-$1.json.gz") core"
}
mpstat_cores() {
    python3 - "$1" <<'PY'
import gzip, json, statistics, sys
try:
    host = json.loads(gzip.open(sys.argv[1]).read())["sysstat"]["hosts"][0]
    loads = [next(c for c in s["cpu-load"] if c["cpu"] == "all") for s in host["statistics"]]
    n = host["number-of-cpus"]
    print("%.2f" % (n - statistics.mean(c["idle"] + c["iowait"] for c in loads) * n / 100))
except Exception:
    print("-")
PY
}

# รอบ idle: CPU ตอนไม่มี traffic ของ mode นี้ นาน IDLE_DURATION  report หักออกจากรอบอื่นของข้อและ mode เดียวกัน
#   idle_round <id ของ mode> "<key=value ...>"
idle_round() {
    IDLE_OUT=$RUN_DIR/$1-idle-r$rep
    round_begin $1-idle $IDLE_DURATION "kind=idle $2" || return 0
    reset_b
    read_counters 0
    cpu_begin
    traffic sleep $IDLE_DURATION
    cpu_end
    read_counters 1
    round_end
    show_cpu b
}

# --- คำสั่งอ่านค่าที่ใช้หลายข้อ (ส่งให้ cmd  ตัวแปรในคำสั่งถูกแทนบนเครื่องปลายทาง) ---
B_NIC='cat /sys/class/net/$LB_IFACE/statistics'      # ต่อท้ายด้วย /rx_packets /tx_packets /rx_bytes /rx_missed_errors
C_NIC='cat /sys/class/net/$SERVER_IFACE/statistics'
B_STATS='$REPO/xdp_lb_ctl stats'                     # ตัวนับของ xdp_lb (xdp_redirect conn_new frag_hit ...)
B_PROG='bpftool prog show pinned $PIN/prog'          # run_cnt และ run_time_ns ของ prog (ต้องเปิด bpf_stats)
# UDP ที่ backend ทั้ง 3 ตัวรับ (port VPORT) และ datagram fragment จาก A ที่ประกอบแล้ว (port VPORT_FRAG)
C_UDP_IN='for i in 1 2 3; do ip netns exec server_$i nft list counter inet perf_sink udp_in; done | awk "\$1 == \"packets\" {s += \$2} END {print s}"'
C_UDP_FRAG_IN='for i in 1 2 3; do ip netns exec server_$i nft list counter inet perf_sink udp_frag_in; done | awk "\$1 == \"packets\" {s += \$2} END {print s}"'
# request ที่ nginx ของ backend แต่ละตัวตอบแล้ว (stub_status)  ผล "b1 <n>" "b2 <n>" "b3 <n>"
C_REQUESTS='for i in 1 2 3; do echo b$i $(ip netns exec server_$i curl -s --max-time 1 http://$(backend_ip $i):$VPORT/nginx_status | awk "NR == 3 {print \$3}"); done'

flow_meta() { echo "profile=$1 ports=$2 threads=${3:-$PKTGEN_THREADS} src_per_thread=$SRC_PER_THREAD duration=$DURATION"; }
http_meta() { echo "http_tool=$HTTP_TOOL conns=$CONNS http_threads=$HTTP_THREADS keepalive_reqs=$KEEPALIVE_REQS http_duration=$HTTP_DURATION"; }
ports_of() { if [ $1 = new ]; then echo $NEW_PORTS; else echo $EST_PORTS; fi; }

# --- C0 จากข้อ 0: c0.tsv ใน RUN_DIR และใน results/<CAMPAIGN>/0.x/ (scenario workload C0 link_bound b1_thr b2_thr b3_thr) ---
#   report.py สร้างใหม่เมื่อมีผลข้อ 0 ที่ใหม่กว่าไฟล์  ทุกฟังก์ชันอ่านจากไฟล์นี้ ไม่ parse ผลของข้อ 0 ซ้ำ
c0_files() {
    local dir
    for dir in "$RUN_DIR" "$RESULTS"/0.*; do
        [ -d "$dir" ] || continue
        if [ ! -f "$dir/c0.tsv" ] || [ -n "$(find "$dir" -maxdepth 1 -name '0.*.meta' -newer "$dir/c0.tsv" | head -1)" ]; then
            python3 "$SCRIPT_DIR/report.py" --c0-table "$dir" >/dev/null 2>&1 || true
        fi
        if [ -f "$dir/c0.tsv" ]; then echo "$dir/c0.tsv"; fi
    done
}
c0_field() { awk -v s=$1 -v w=$2 -v f=$3 '$1 == s && $2 == w {print $f; exit}' $(c0_files) /dev/null 2>/dev/null || true; }
c0() { local value; value=$(c0_field $1 $2 3); echo ${value:-0}; }
need_c0() {
    local scenario=$1 load
    shift
    if [ -n "$PLAN" ]; then return 0; fi
    for load in "$@"; do
        if [ -z "$(c0_field $scenario $load 3)" ]; then
            echo "ยังไม่มี C0 ของ scenario=$scenario workload=$load ใน $RESULTS/0.x  รัน tcase/0.x.sh ของชุด $CAMPAIGN ก่อน"
            exit 1
        fi
    done
}
# levels <scenario> <workload> "<ระดับ ...>" -> <ระดับ>:<req/s>  ระดับเป็น % ของ C0 (open-loop)
levels() {
    local cap level
    cap=$(c0 $1 $2)
    for level in $3; do echo $level:$(( cap * level / 100 )); done
}
level_meta() { echo "level=${3%:*} rate=${3#*:} c0_scenario=$1 c0=$(c0 $1 $2) $(http_meta)"; }

use_mode() { on_b mode $1 ${2:-} >/dev/null; on_c mode $(c_mode_for $1); }

# B_REST_MODE=none ระหว่างช่วง B ของชุดใหม่: ไม่ใส่ XDP คืนตอนจบข้อ (ใส่/ถอด XDP ทำให้การ์ดของ B reset)
restore() {
    on_c mode guarded
    on_c quota ${QUOTA[equal]} >/dev/null
    on_c probe-drop 0
    on_b mode ${B_REST_MODE:-xdp} >/dev/null
}

# --- ข้อ 4 และ 5 ---

# ชุดอัลกอริทึมของข้อ 4 แปลงเป็นคำสั่ง algo ของ setup_b_lb.sh
# algo ของ reset สำหรับ variant ข้อ 4  <variant> <scenario ของ quota ตอนเริ่มรอบ>
variant_algo() {
    case $1 in
        xdp:wcmp)  echo wcmp 4 ;;
        xdp:lcf)   echo lcf 500 ;;
        xdp:awfd*) echo awfd ${1#xdp:awfd} 500 ;;
        ipvs:wlc|nginx:least_conn|haproxy:leastconn) echo ${1#*:} ${QUOTA[$2]//%/} ;;
        *)         echo ${1#*:} ;;
    esac
}
# ข้อ 4: ไม่ผสม xdp กับ LB อื่นในการรันเดียว  รันของ LB อื่นจบแล้วไม่ใส่ XDP คืน (B_REST_MODE=none)
check_variants() {
    local kinds
    kinds=$(for variant in $TEST4_VARIANTS; do [ ${variant%%:*} = xdp ] && echo xdp || echo other; done | sort -u)
    [ $(wc -l <<< "$kinds") = 1 ] || { echo "TEST4_VARIANTS ผสม xdp กับ LB อื่น  แยกรันเป็นคนละครั้ง"; exit 1; }
    [ "$kinds" = xdp ] || B_REST_MODE=${B_REST_MODE:-none}
}


# --- plan: นับรอบและเวลาโดยไม่ยิงจริง ---

# เวลาเสียต่อรอบ: OVERHEAD ถ้าตั้งไว้, ไม่งั้นค่าเฉลี่ย gap_ms ใน RUN_DIR, ไม่มีก็ 5 s
overhead() {
    read -r OVERHEAD_MS GAP_ROUNDS <<< "$(cat "$RUN_DIR"/*.meta 2>/dev/null |
        awk -F= '$1 == "gap_ms" {sum += $2; n++} END {if (n) printf "%d %d", sum / n, n}')"
    if [ -n "$OVERHEAD" ]; then OVERHEAD_MS=$(awk -v s=$OVERHEAD 'BEGIN {printf "%d", s * 1000}') GAP_ROUNDS=""; fi
    OVERHEAD_MS=${OVERHEAD_MS:-5000}
}
hours() { awk -v ms=$1 'BEGIN {printf "%.2f", ms / 3600000}'; }

# plan_of <ข้อ ...> -> หนึ่งบรรทัดต่อข้อ "ข้อ รอบ รอบที่ยังไม่เสร็จ ms ms_ที่ยังไม่เสร็จ"
#   รันฟังก์ชันของข้อในโหมด PLAN ใน subshell เดียวกัน รอบที่ใช้ร่วมกัน (control ของข้อ 5) จึงนับครั้งเดียว
plan_one() {
    local TEST=$1
    PLAN_ROUNDS=0 PLAN_LEFT=0 PLAN_MS=0 PLAN_LEFT_MS=0
    t${TEST/./_} >/dev/null
    echo $TEST $PLAN_ROUNDS $PLAN_LEFT $PLAN_MS $PLAN_LEFT_MS
}
plan_of() { ( PLAN=1; for id in "$@"; do plan_one $id; done ) }

plan() {
    local id rounds left ms left_ms notes sum=(0 0 0 0)
    local -A RAN=()                                     # นับทุกรอบ แม้รอบที่รันไปแล้วในการรันครั้งนี้
    notes=$(mktemp)
    echo "แผนของ $RUN_DIR   เวลาเสียต่อรอบ $(awk -v ms=$OVERHEAD_MS 'BEGIN {printf "%.1f", ms / 1000}') s" \
         "($([ -n "$GAP_ROUNDS" ] && echo "ค่าเฉลี่ยจาก $GAP_ROUNDS รอบ" || echo "OVERHEAD หรือค่าเริ่มต้น"))"
    echo "  ข้อ     รอบ      ชม.   ยังไม่เสร็จ      ชม."
    while read -r id rounds left ms left_ms; do
        printf '  %-5s %5d %8s %10d %9s\n' $id $rounds $(hours $ms) $left $(hours $left_ms)
        sum=($(( sum[0] + rounds )) $(( sum[1] + ms )) $(( sum[2] + left )) $(( sum[3] + left_ms )))
    done < <(plan_of "${selected[@]}" 2>>"$notes")
    printf '  %-5s %5d %8s %10d %9s\n' all ${sum[0]} $(hours ${sum[1]}) ${sum[2]} $(hours ${sum[3]})
    sort -u "$notes" | sed 's/^/  * /'
    rm -f "$notes"
}

# ตอนเริ่มแต่ละข้อ: จำนวนรอบและเวลาที่คาดว่าจะเสร็จ
eta() {
    local rounds left ms left_ms
    overhead
    read -r _ rounds left ms left_ms <<< "$(plan_of $TEST 2>/dev/null)"
    echo "   ${rounds:-0} รอบ (ยังไม่เสร็จ ${left:-0})  ประมาณ $(( ${left_ms:-0} / 60000 )) นาที" \
         "เสร็จราว $(date -d "+$(( ${left_ms:-0} / 1000 )) seconds" +%H:%M)"
}

# --- เริ่มและจบการรันของไฟล์ข้อย่อย ---

# start_run "<คำสั่งที่รัน>": root, pktgen, MAC ของ B C, route ไป VIP, สภาพเครื่อง A B C ลง env-*.txt (preamble เดิม)
start_run() {
    require_root
    modprobe pktgen
    mkdir -p "$RUN_DIR"
    echo "=== $(date '+%F %T')  $*" >> "$RUN_DIR/env-a.txt"
    LB_MAC=$(mac_of $LB_IP)
    SERVER_MAC=$(mac_of $SERVER_IP)
    [ -n "$LB_MAC" ] && [ -n "$SERVER_MAC" ] || { echo "หา MAC ของ B หรือ C ไม่ได้"; exit 1; }
    vip_route mtu lock $VIP_MTU
    on_b status >/dev/null
    on_c status >/dev/null
    {
        env_info $CLIENT_IFACE
        ip route get $VIP
        echo "== settings  HTTP_TOOL=$HTTP_TOOL RAW_TOOL=$RAW_TOOL RESUME=$RESUME"
        declare -p DURATION HTTP_DURATION HTTP_DURATION_DYNAMIC IDLE_DURATION REPS_UDP REPS_TEST2 REPS_TEST3 REPS_HTTP \
            SETTLE PPS_LADDER SIZES SIZE_SWEEP_PPS STRESS_PPS PKTGEN_THREADS SRC_PER_THREAD EST_PORTS NEW_PORTS CONNS \
            HTTP_THREADS SAT_RATE STREAMS WEB_FILES TEST1_MODES TEST12_LEVELS LAT_RATE VIP_COUNTS TEST2_PPS TEST3_PPS \
            FRAG_TOTAL_PPS FRAG_PERCENTS PMTU_PPS FLOOD_RATE FRAG_FLOW_RATE TEST4_VARIANTS TEST4_LEVELS \
            TEST4_SAT_REPS QUOTA TEST4_SCENARIOS VIP_MTU
    } >> "$RUN_DIR/env-a.txt"
    { echo "=== $(date '+%F %T')"; on_b env; } >> "$RUN_DIR/env-b.txt"
    { echo "=== $(date '+%F %T')"; on_c env; } >> "$RUN_DIR/env-c.txt"
    KEEPALIVE_REQS=$(sed -n 's/^nginx_keepalive_requests=//p' "$RUN_DIR/env-c.txt" | tail -1)
    SEQ=$(cat "$RUN_DIR"/*.meta 2>/dev/null | sed -n 's/^seq=//p' | sort -n | tail -1)
    SEQ=${SEQ:-0}
    overhead
    {   # ค่าจริงของเครื่อง: interface อ่านจาก perf_env.sh ของเครื่องนั้น
        echo "== ค่าจริง  A $CLIENT_IFACE $CLIENT_IP  B $(remote b 'echo $LB_IFACE') $LB_IP $LB_MAC" \
             " C $(remote c 'echo $SERVER_IFACE') $SERVER_IP $SERVER_MAC"
        echo "   VIP $VIP  backend $(backend_ip 1) $(backend_ip 2) $(backend_ip 3)"
    } | tee -a "$RUN_DIR/env-a.txt"
}

# run_one <ข้อ> [plan | report [dir]]: บรรทัดสุดท้ายของไฟล์ข้อย่อย  ไม่ใส่อะไร = รันข้อนั้นแล้วสรุปด้วย report.py
run_one() {
    TEST=$1
    RUN_DIR=${USER_RUN_DIR:-$RESULTS/$TEST}
    shift
    case "${1:-}" in
        "")     ;;
        plan)   overhead; selected=($TEST); plan; exit 0 ;;
        report) exec python3 "$SCRIPT_DIR/report.py" "${2:-$RUN_DIR}" ;;
        *)      echo "ใช้: $0 [plan | report [dir]]   ปรับค่าผ่าน env ได้ เช่น REPS=1 DURATION=5 $0"; exit 1 ;;
    esac
    start_run "tcase/$TEST.sh"
    echo "== ข้อ $TEST  ($(date +%H:%M:%S))  ผลอยู่ที่ $RUN_DIR"
    eta
    t${TEST/./_}
    python3 "$SCRIPT_DIR/report.py" "$RUN_DIR" | tee "$RUN_DIR/report.txt"
}
