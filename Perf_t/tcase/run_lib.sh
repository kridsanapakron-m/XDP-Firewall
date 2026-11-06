#!/bin/bash
set -e

TCASE_DIR=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
SCRIPT_DIR=$(dirname "$TCASE_DIR")
source "$SCRIPT_DIR/perf_env.sh"
CAMPAIGN=${CAMPAIGN:-20261018}
RESULTS=$SCRIPT_DIR/results/$CAMPAIGN

SETTLE=${SETTLE:-1}
PKTGEN_THREADS=${PKTGEN_THREADS:-2}
SRC_PER_THREAD=125
EST_PORTS=${EST_PORTS:-4}
NEW_PORTS=${NEW_PORTS:-64511}
CONNS=${CONNS:-128}
HTTP_THREADS=${HTTP_THREADS:-4}
SAT_RATE=${SAT_RATE:-2000000}
STREAMS=${STREAMS:-16}
TEST4_AWFD_TUNE=${TEST4_AWFD_TUNE:-"30 25"}
declare -A QUOTA=(
    [equal]=${QUOTA_EQUAL:-"100% 100% 100%"}
    [unequal]=${QUOTA_UNEQUAL:-"100% 50% 25%"}
    [1-1-1]="40% 40% 40%"
    [1-1-0.5]="40% 40% 20%"
    [1-0.5-0.5]="40% 20% 20%"
    [1-0.5-0.25]="40% 20% 10%"
    [dynamic_after]="40% 40% 20%"
)
TEST4_SCENARIOS="1-1-1 1-1-0.5 1-0.5-0.5 1-0.5-0.25"

ssh_options="-o BatchMode=yes -o ConnectTimeout=5 -o ControlMaster=auto -o ControlPersist=10m"

source "$TCASE_DIR/cmd.sh"

on_b() { ssh $ssh_options $SSH_LB "$PERF_DIR/setup_b_lb.sh $*"; }
on_c() { ssh $ssh_options $SSH_SERVER "$PERF_DIR/setup_c_server.sh $*"; }
vip_route() { ip route replace $VIP/32 dev $CLIENT_IFACE "$@"; }

c_mode_for() { case $1 in nft|ipt) echo nat ;; *) echo guarded ;; esac; }
gcd() { if (( $2 )); then gcd $2 $(( $1 % $2 )); else echo $1; fi; }
lcm() { echo $(( $1 * $2 / $(gcd $1 $2) )); }
share() { echo $(( $1 * $2 / 3 - $1 * ($2 - 1) / 3 )); }
pgset() { echo "pgset $1: $2"; echo "$2" > /proc/net/pktgen/$1; }
show() { echo "# $*"; "$@"; }

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
        pgset $device "udp_src_max $(( 1024 + ports ))"
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

hping() {
    local kind=$1 rate=$2 seconds=$3 start output sent
    shift 3
    start=$(date +%s%N)
    output=$(show timeout -s INT -k 5 $seconds hping3 -q -i u$(( 1000000 / rate )) "$@" 2>&1) || true
    echo "$output"
    sent=$(awk '/packets tra[a-z]*itted/ {print $1}' <<< "$output")
    [ -n "$sent" ] || return 1
    echo "traffic: tool=hping3 kind=$kind sent=$sent target_pps=$rate" \
         "achieved_pps=$(( sent * 1000000000 / ($(date +%s%N) - start) ))"
}

replay() {
    local kind=$1 rate=$2 output
    output=$(show tcpreplay -i $CLIENT_IFACE -K --pps=$(( rate * $5 )) --duration=$3 --loop=0 $4 2>&1) || true
    echo "$output"
    grep -q '^Actual: [0-9]* packets' <<< "$output" || return 1
    awk -v kind=$kind -v rate=$rate -v per=$5 '/^Actual: [0-9]+ packets/ {
        printf "traffic: tool=tcpreplay kind=%s sent=%d packets=%d target_pps=%d achieved_pps=%d\n",
               kind, $2 / per, $2, rate, $2 / per / $(NF - 1) }' <<< "$output"
}

make_frag_packet_file() {
    local file=$RUN_DIR/frag$1.pcap
    [ -f $file ] || python3 - $file $1 $(cat /sys/class/net/$CLIENT_IFACE/address) $LB_MAC \
        $CLIENT_IP $VIP $VPORT_FRAG <<'PY'
import socket, struct, sys
path, count, src_mac, dst_mac, src, dst, port = sys.argv[1:]
count, piece = int(count), 56
ethernet = bytes.fromhex(dst_mac.replace(":", "") + src_mac.replace(":", "")) + b"\x08\x00"

def packet(ident, flags_offset, payload):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, flags_offset, 64, 17, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    total = sum(struct.unpack("!10H", header))
    checksum = ~((total & 0xffff) + (total >> 16)) & 0xffff
    return ethernet + header[:10] + struct.pack("!H", checksum) + header[12:] + payload

with open(path, "wb") as out:
    out.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for ident in range(16384):
        datagram = struct.pack("!HHHH", 1024 + ident % 1000, int(port), piece * count, 0) + bytes(piece * count - 8)
        for i in range(count):
            more = 0x2000 if i < count - 1 else 0
            data = packet(ident, more | i * piece // 8, datagram[i * piece:(i + 1) * piece])
            out.write(struct.pack("<IIII", 0, 0, len(data), len(data)) + data)
PY
    echo $file
}

frag() { replay frag $(( $2 / $1 )) $3 $(make_frag_packet_file $1) $1; }

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

raw() { hping $1 $2 $3 --udp -p $VPORT -y -d $(( ${1#df} - 28 )) $VIP; }

http() {
    local host=$1 file=$2 rate=$3 conns=$4 close=${5:+-H Connection:close}
    local threads=$(( conns < HTTP_THREADS ? conns : HTTP_THREADS )) url=http://$1:$VPORT/f${2/mix/1k}
    [ $rate = sat ] && rate=$SAT_RATE
    show wrk2 -t $threads -c $conns -d ${HTTP_DURATION}s -R $rate --latency $close \
        $([ $file = mix ] && echo -s $(mix_lua)) $url
}

web_file() { local file=${1#web-}; echo ${file%-close}; }
close_of() { if [[ $1 == *-close ]]; then echo close; fi; }

via_vip() {
    if [ $1 = elephant ]; then
        show iperf -c $VIP -p $IPERF_PORT -P $STREAMS -t $HTTP_DURATION -f m
    else
        http $VIP $(web_file $1) $2 $CONNS $(close_of $1)
    fi
}

part_of() { if [ -n "$weighted" ]; then echo $(( $1 * weights[$2 - 1] / sum )); else share $1 $2; fi; }

direct3() {
    local load=$1 rate=$2 weights=(${3:-1 1 1}) weighted=${3:-} i part pids=() failed=0 HTTP_THREADS=$(( (HTTP_THREADS + 2) / 3 ))
    local sum=$(( weights[0] + weights[1] + weights[2] ))
    for i in $BACKENDS; do
        {
            echo "## backend $i"
            if [ $load = elephant ]; then
                show iperf -c $(backend_ip $i) -p $IPERF_PORT -P $(share $STREAMS $i) -t $HTTP_DURATION -f m
            else
                http $(backend_ip $i) $(web_file $load) $(if [ $rate = sat ]; then echo sat; else part_of $rate $i; fi) \
                    $(part_of $CONNS $i) $(close_of $load)
            fi
        } > "$out.part$i" 2>&1 &
        pids+=($!)
    done
    for i in "${pids[@]}"; do wait $i || failed=1; done
    cat "$out".part*
    rm -f "$out".part*
    return $failed
}

traced() {
    local status=0
    on_b lookup start || return 1
    "$@" || status=$?
    on_b lookup stop > "$out.lookup"
    return $status
}

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

snapshot_all() {
    local a b
    host_snapshot $CLIENT_IFACE > "$1.a$2" &
    a=$!
    on_b snapshot > "$1.b$2" &
    b=$!
    on_c snapshot > "$1.c$2"
    wait $a $b
}

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

flow_meta() { echo "profile=$1 ports=$2 threads=${3:-$PKTGEN_THREADS} src_per_thread=$SRC_PER_THREAD duration=$DURATION"; }
http_meta() { echo "http_tool=wrk2 conns=$CONNS http_threads=$HTTP_THREADS keepalive_reqs=$KEEPALIVE_REQS http_duration=$HTTP_DURATION"; }
ports_of() { if [ $1 = new ]; then echo $NEW_PORTS; else echo $EST_PORTS; fi; }

read -r -d '' PERF_START_B <<'EOF' || true
setsid perf stat -a -A -e cycles,ref-cycles -I 1000 -x, -o /run/perf-b.csv < /dev/null > /dev/null 2>&1 &
echo $! > /run/perf-b.pid
EOF
PERF_STOP_B='pid=$(cat /run/perf-b.pid); kill -INT $pid; while kill -0 $pid 2>/dev/null; do sleep 0.1; done; cat /run/perf-b.csv'

perf_prereq() {
    ! curl -s -m 2 -o /dev/null http://$LB_IP:9100/metrics ||
        { echo "node_exporter บน B ยังทำงาน  สั่ง /opt/monitor/monitor.sh stop บน A ก่อน"; exit 1; }
    TSC_MHZ=$(remote b "turbostat --quiet --show TSC_MHz --interval 1 --num_iterations 1 2>/dev/null" | awk 'NR == 2 {print $1}')
    [[ "$TSC_MHZ" =~ ^[0-9]+$ ]] || { echo "อ่าน TSC ของ B ไม่ได้ (turbostat)"; exit 1; }
}

read_perf_begin() { remote b "$PERF_START_B"; }

read_perf_end() {
    remote b "$PERF_STOP_B" > "$out.perf.csv"
    awk -F, -v tsc=$TSC_MHZ '
        $5 == "cycles" { cycles += $3 }
        $5 == "ref-cycles" {
            if ($1 != t) { t = $1; dt[++k] = $1 - last; last = $1 }
            ref[k, $2] += $3; cpus[$2] = 1; busy_s += $3 / (tsc * 1e6)
        }
        END {
            for (i = 2; i < k; i++) {
                c = 0
                for (cpu in cpus) { c += ref[i, cpu]; mid[cpu] += ref[i, cpu]; span += cpu == "CPU0" ? dt[i] : 0 }
                c /= dt[i] * tsc * 1e6; sum += c
                if (i == 2 || c < lo) lo = c
                if (i == 2 || c > hi) hi = c
            }
            m = k > 2 ? k - 2 : 1
            for (cpu in cpus) if (mid[cpu] > hot) hot = mid[cpu]
            printf "b_cpu_cores=%.3f\nb_cpu_cores_min=%.3f\nb_cpu_cores_max=%.3f\nb_cpu_hot_pct=%.1f\n",
                   sum / m, lo, hi, (span > 0 ? hot / (span * tsc * 1e6) * 100 : 0)
            printf "b_cpu_busy_s=%.3f\nb_cpu_cycles=%.0f\nb_perf_seconds=%d\nb_tsc_mhz=%s\n", busy_s, cycles, k, tsc
        }' "$out.perf.csv" >> "$out.meta"
}

read -r -d '' ONE_CORE_B <<'EOF' || true
irqs=$(awk -v d=$LB_IFACE '$0 ~ d {sub(":", "", $1); print $1}' /proc/interrupts)
for irq in $irqs; do echo 0 > /proc/irq/$irq/smp_affinity_list; done
if [ -f /run/perf-lb-nginx.pid ]; then
    master=$(cat /run/perf-lb-nginx.pid)
    sed -i 's/worker_processes auto;/worker_processes 1; worker_cpu_affinity 1;/' /etc/nginx/perf-lb.conf
    kill $master
    while kill -0 $master 2>/dev/null; do sleep 0.1; done
    taskset -c 0 nginx -c /etc/nginx/perf-lb.conf < /dev/null >> /var/log/perf-lb-nginx.err 2>&1
    sleep 0.5
    echo "b_nginx_worker_cpus=$(ps -o psr= --ppid $(cat /run/perf-lb-nginx.pid) | tr -d ' ' | sort -u | paste -sd, -)"
fi
echo "b_irq_cpus=$(for irq in $irqs; do cat /proc/irq/$irq/smp_affinity_list; done | sort -u | paste -sd, -)"
echo "b_rps_cpus=$(cat /sys/class/net/$LB_IFACE/queues/rx-*/rps_cpus | sort -u | paste -sd, -)"
EOF

read -r -d '' END_B <<'EOF' || true
kill -INT $(cat /run/perf16.pid 2>/dev/null) 2>/dev/null
core=0
for irq in $(awk -v d=$LB_IFACE '$0 ~ d {sub(":", "", $1); print $1}' /proc/interrupts); do
    echo $((core % QUEUES)) > /proc/irq/$irq/smp_affinity_list
    core=$((core + 1))
done
EOF

read -r -d '' CORE0_START_B <<'EOF' || true
taskset -apc 1-3,5-7 $(pgrep -x mpstat) > /dev/null
setsid taskset -c 3 perf stat -C 0,4 -A -e cycles,ref-cycles -I 1000 -x, -o /run/perf16.csv < /dev/null > /dev/null 2>&1 &
echo $! > /run/perf16.pid
EOF
CORE0_STOP_B='pid=$(cat /run/perf16.pid); kill -INT $pid; while kill -0 $pid 2>/dev/null; do sleep 0.1; done; cat /run/perf16.csv'

read_core0_begin() { remote b "$CORE0_START_B"; }

read_core0_end() {
    remote b "$CORE0_STOP_B" > "$out.perf.csv"
    awk -F, -v tsc=$TSC_MHZ '
        $5 == "cycles" && $2 == "CPU0" { cycles += $3 }
        $5 == "ref-cycles" {
            dt = $1 - last[$2]; last[$2] = $1
            busy_s[$2] += $3 / (tsc * 1e6)
            pct[$2, ++n[$2]] = $3 / (dt * tsc * 1e6) * 100
        }
        END {
            for (i = 2; i < n["CPU0"]; i++) {
                p = pct["CPU0", i]; sum += p; sum4 += pct["CPU4", i]
                if (i == 2 || p < lo) lo = p
                if (i == 2 || p > hi) hi = p
            }
            m = n["CPU0"] > 2 ? n["CPU0"] - 2 : 1
            printf "b_cpu0_busy_pct=%.1f\nb_cpu0_busy_min=%.1f\nb_cpu0_busy_max=%.1f\nb_cpu4_busy_pct=%.1f\n", sum / m, lo, hi, sum4 / m
            printf "b_cpu0_busy_s=%.3f\nb_cpu0_cycles=%.0f\nb_perf_seconds=%d\nb_tsc_mhz=%s\n", busy_s["CPU0"], cycles, n["CPU0"], tsc
        }' "$out.perf.csv" >> "$out.meta"
}

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
levels() {
    local cap level
    cap=$(c0 $1 $2)
    for level in $3; do echo $level:$(( cap * level / 100 )); done
}
level_meta() { echo "level=${3%:*} rate=${3#*:} c0_scenario=$1 c0=$(c0 $1 $2) $(http_meta)"; }

restore() {
    on_c mode guarded
    on_c quota ${QUOTA[equal]} >/dev/null
    on_c probe-drop 0
    on_b mode ${B_REST_MODE:-xdp} >/dev/null
}

variant_algo() {
    case $1 in
        xdp:awfd4s) echo awfd 4 500 $TEST4_AWFD_TUNE ;;
        ipvs:wlc|nginx:least_conn|haproxy:leastconn) echo ${1#*:} ${QUOTA[$2]//%/} ;;
        *)         echo ${1#*:} ;;
    esac
}

begin_round() {
    id=$1 out=$RUN_DIR/$1-r$rep
    [ ! -e "$out.meta" ] || { echo "มีผลของรอบนี้แล้ว: $out.meta  ใช้ RUN_DIR หรือ CAMPAIGN ใหม่"; exit 1; }
    SEQ=$(( SEQ + 1 ))
    tr ' ' '\n' <<< "case=$id rep=$rep seq=$SEQ $2" > "$out.meta"
    echo "  $id r$rep"
}

reset_lb() {
    if [ -n "${B_OFF_PATH:-}" ]; then echo "b_mode=none" >> "$out.meta"; else on_b reset ${RESET_ARGS:-} >> "$out.meta"; fi
    sleep $SETTLE
}

reset_lb_one_core() {
    local pinned
    reset_lb
    pinned=$(remote b "$ONE_CORE_B")
    echo "$pinned" >> "$out.meta"
    grep -q '^b_irq_cpus=0$' <<< "$pinned" && grep -Eq '^b_rps_cpus=[0,]+$' <<< "$pinned" &&
        { ! grep -q '^b_nginx' <<< "$pinned" || grep -q '^b_nginx_worker_cpus=0$' <<< "$pinned"; } ||
        { echo "B ไม่ได้ใช้ core 0 core เดียว  หยุด"; exit 1; }
}

read_counters_begin() { snapshot_all "$out" 0; }
read_counters_end() { snapshot_all "$out" 1; }
read_cpu_begin() { cpu_all start; }
read_cpu_end() { cpu_all stop "$out"; }

run_traffic() {
    echo "# command: $*" > "$out.client"
    echo "t_start_ns=$(date +%s%N)" >> "$out.meta"
    "$@" >> "$out.client" 2>&1 || echo "traffic_error=1" >> "$out.meta"
    echo "t_end_ns=$(date +%s%N)" >> "$out.meta"
}

run_idle_round() {
    begin_round $1-idle "kind=idle $2"
    reset_lb
    read_counters_begin
    read_cpu_begin
    run_traffic sleep $IDLE_DURATION
    read_cpu_end
    read_counters_end
}

run_idle_perf() {
    begin_round $1-idle "kind=idle $2"
    reset_lb
    read_counters_begin
    read_cpu_begin
    read_perf_begin
    run_traffic sleep $IDLE_DURATION
    read_perf_end
    read_cpu_end
    read_counters_end
}

run_idle_one_core() {
    begin_round $1-idle "kind=idle $2"
    reset_lb_one_core
    read_counters_begin
    read_cpu_begin
    read_core0_begin
    run_traffic sleep $IDLE_DURATION
    read_core0_end
    read_cpu_end
    read_counters_end
}

prepare_perf() {
    perf_prereq
    trap 'remote b "kill -INT \$(cat /run/perf-b.pid 2>/dev/null) 2>/dev/null; true"' EXIT
}

prepare_one_core() {
    perf_prereq
    trap 'remote b "$END_B"' EXIT
}

need_c0() {
    local scenario=$1 load
    shift
    for load in "$@"; do
        if [ -z "$(c0_field $scenario $load 3)" ]; then
            echo "ยังไม่มี C0 ของ scenario=$scenario workload=$load ใน $RESULTS/0.x  รันข้อ 0 ก่อน"
            exit 1
        fi
    done
}

select_lb() {
    local lb
    for lb in "$@"; do
        case $GROUP:$lb in :*|xdp:xdp*|xdp:direct|other:[!xd]*) echo $lb ;; esac
    done
}

switch_lb() { on_b mode $1 ${2:-} >/dev/null; on_c mode $(c_mode_for $1); }

check_test4() {
    need_c0 $1 web-1k
    [ "$(c0_field $1 web-1k 4)" != 1 ] || { echo "C0 ของ $1 ใช้สายเกิน 90% (link-bound)  ลด QUOTA ของข้อ 4 ก่อน"; exit 1; }
    [ -n "$GROUP" ] || { echo "ใช้: $0 xdp | other   (ไม่รวมกันเพื่อลดการ reset การ์ดของ B)"; exit 1; }
}

test4_levels() {
    levels $1 web-1k "$TEST4_LEVELS"
    if [ $rep -le $(case $2 in *awfd4s) echo 3 ;; *) echo 1 ;; esac) ]; then echo sat:sat; fi
}

start_test() {
    TEST=$1 GROUP=${2:-}
    [[ "$GROUP" =~ ^(xdp|other|)$ ]] || { echo "ใช้: $0 [xdp | other]"; exit 1; }
    [ "$GROUP" != other ] || B_REST_MODE=${B_REST_MODE:-none}
    RUN_DIR=${RUN_DIR:-$RESULTS/$TEST}
    require_root
    modprobe pktgen
    mkdir -p "$RUN_DIR"
    echo "=== $(date '+%F %T')  tcase/$TEST.sh" >> "$RUN_DIR/env-a.txt"
    LB_MAC=$(mac_of $LB_IP)
    SERVER_MAC=$(mac_of $SERVER_IP)
    [ -n "$LB_MAC" ] && [ -n "$SERVER_MAC" ] || { echo "หา MAC ของ B หรือ C ไม่ได้"; exit 1; }
    vip_route mtu lock $VIP_MTU
    on_b status >/dev/null
    on_c status >/dev/null
    {
        env_info $CLIENT_IFACE
        ip route get $VIP
        echo "== settings  http_tool=wrk2 raw_tool=hping3"
        declare -p REPS DURATION HTTP_DURATION IDLE_DURATION SETTLE PKTGEN_THREADS SRC_PER_THREAD EST_PORTS NEW_PORTS \
            CONNS HTTP_THREADS SAT_RATE STREAMS QUOTA VIP_MTU 2>/dev/null || true
    } >> "$RUN_DIR/env-a.txt"
    { echo "=== $(date '+%F %T')"; on_b env; } >> "$RUN_DIR/env-b.txt"
    { echo "=== $(date '+%F %T')"; on_c env; } >> "$RUN_DIR/env-c.txt"
    KEEPALIVE_REQS=$(sed -n 's/^nginx_keepalive_requests=//p' "$RUN_DIR/env-c.txt" | tail -1)
    SEQ=$(cat "$RUN_DIR"/*.meta 2>/dev/null | sed -n 's/^seq=//p' | sort -n | tail -1)
    SEQ=${SEQ:-0}
    echo "== ข้อ $TEST  ($(date +%H:%M:%S))  ผลอยู่ที่ $RUN_DIR"
}

write_result() { python3 "$SCRIPT_DIR/report.py" "$RUN_DIR" | tee "$RUN_DIR/report.txt"; }
