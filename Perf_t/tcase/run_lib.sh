#!/bin/bash
set -e

TCASE_DIR=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
SCRIPT_DIR=$(dirname "$TCASE_DIR")
source "$SCRIPT_DIR/perf_env.sh"
CAMPAIGN=${CAMPAIGN:-20261018}
RESULTS=$SCRIPT_DIR/results/$CAMPAIGN
USER_RUN_DIR=${RUN_DIR:-}
RUN_DIR=${RUN_DIR:-$RESULTS}

DURATION=${DURATION:-20}
HTTP_DURATION=${HTTP_DURATION:-40}
HTTP_DURATION_DYNAMIC=${HTTP_DURATION_DYNAMIC:-60}
IDLE_DURATION=${IDLE_DURATION:-10}
REPS_UDP=${REPS_UDP:-${REPS:-10}}
REPS_TEST2=${REPS_TEST2:-${REPS:-10}}
REPS_TEST3=${REPS_TEST3:-${REPS:-10}}
REPS_HTTP=${REPS_HTTP:-${REPS:-10}}
SETTLE=${SETTLE:-1}
RESUME=${RESUME:-1}
OVERHEAD=${OVERHEAD:-}
PPS_LADDER=${PPS_LADDER:-"50000 100000 250000 500000 750000 1000000"}
SIZES=${SIZES:-"64 512 1024 1400"}
SIZE_SWEEP_PPS=${SIZE_SWEEP_PPS:-50000}
STRESS_PPS=${STRESS_PPS:-}
PKTGEN_THREADS=${PKTGEN_THREADS:-2}
SRC_PER_THREAD=125
EST_PORTS=${EST_PORTS:-4}
NEW_PORTS=${NEW_PORTS:-64511}
CONNS=${CONNS:-128}
HTTP_THREADS=${HTTP_THREADS:-4}
SAT_RATE=${SAT_RATE:-2000000}
STREAMS=${STREAMS:-16}
WEB_FILES=${WEB_FILES:-"1k 10k 100k 1m mix"}
HTTP_TOOL=${HTTP_TOOL:-$(command -v wrk2 >/dev/null && echo wrk2 || echo h2load)}
RAW_TOOL=${RAW_TOOL:-hping3}

TEST1_MODES=${TEST1_MODES:-"xdp ipvs nft ipt nginx haproxy"}
TEST12_LEVELS=${TEST12_LEVELS:-75}
LAT_RATE=${LAT_RATE:-1000}
VIP_COUNTS=${VIP_COUNTS:-"1 10 100 1000"}
TEST2_PPS=${TEST2_PPS:-40000}
TEST3_PPS=${TEST3_PPS:-"500000 100000"}
PMTU_PPS=${PMTU_PPS:-50000}
TEST4_VARIANTS=${TEST4_VARIANTS:-"xdp:ecmp xdp:wcmp xdp:awfd4"}
TEST4_LEVELS=${TEST4_LEVELS:-${LOAD_LEVELS:-"50 75 90"}}
TEST4_AWFD_TUNE=${TEST4_AWFD_TUNE:-"30 25"}
TEST4_SAT_REPS=${TEST4_SAT_REPS:-1}
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

PLAN=""
LAST_END_NS=""
declare -A RAN=()

ssh_options="-o BatchMode=yes -o ConnectTimeout=5 -o ControlMaster=auto -o ControlPersist=10m"

source "$TCASE_DIR/cmd.sh"

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

pcap_of() {
    local file=$RUN_DIR/$1.pcap
    [ -f $file ] || python3 - $file $1 $(cat /sys/class/net/$CLIENT_IFACE/address) $LB_MAC \
        $CLIENT_IP $VIP $VPORT <<'PY'
import socket, struct, sys
path, kind, src_mac, dst_mac, src, dst, vport = sys.argv[1:]
ethernet = bytes.fromhex(dst_mac.replace(":", "") + src_mac.replace(":", "")) + b"\x08\x00"

def packet(ident, flags_offset, payload):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, flags_offset, 64, 17, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    total = sum(struct.unpack("!10H", header))
    checksum = ~((total & 0xffff) + (total >> 16)) & 0xffff
    return ethernet + header[:10] + struct.pack("!H", checksum) + header[12:] + payload

packets = []
for ident in range(8192):
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

raw() {
    if [ $RAW_TOOL = tcpreplay ]; then
        replay $1 $2 $3 $(pcap_of $1) 1
    else
        hping $1 $2 $3 --udp -p $VPORT -y -d $(( ${1#df} - 28 )) $VIP
    fi
}

frag_pcap() {
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

frag() { replay frag $(( $2 / $1 )) $3 $(frag_pcap $1) $1; }

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

uri_file() {
    local file=$RUN_DIR/uris-$1.txt entry n
    if [ ! -f $file ]; then
        for entry in f1k:70 f10k:20 f100k:9 f1m:1; do
            for ((n = 0; n < ${entry##*:}; n++)); do echo "http://$1:$VPORT/${entry%%:*}"; done
        done | shuf --random-source=<(yes) > $file
    fi
    echo $file
}

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
        part=.b$i
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

check_rate() {
    awk '/^traffic:/ { for (f = 2; f <= NF; f++) { split($f, kv, "="); v[kv[1]] = kv[2] }
                       if (v["achieved_pps"] + 0 < 0.95 * v["target_pps"]) bad = 1 }
         END { if (bad) print "invalid=rate" }' "$1.client" >> "$1.meta"
}

round_done() {
    [ -f "$1.meta" ] && grep -q '^t_end_ns=' "$1.meta" && ! grep -q '^traffic_error=' "$1.meta" &&
        { ! grep -q '^invalid=' "$1.meta" || grep -q '^link_bound=1$' "$1.meta"; }
}

plan_count() {
    local out=$1 seconds=$2
    PLAN_ROUNDS=$(( PLAN_ROUNDS + 1 )) PLAN_MS=$(( PLAN_MS + seconds * 1000 + OVERHEAD_MS ))
    if [ "$RESUME" != 1 ] || ! round_done "$out"; then
        PLAN_LEFT=$(( PLAN_LEFT + 1 )) PLAN_LEFT_MS=$(( PLAN_LEFT_MS + seconds * 1000 + OVERHEAD_MS ))
    fi
}

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

reset_b() {
    if [ -n "${B_OFF_PATH:-}" ]; then echo "b_mode=none" >> "$out.meta"; else on_b reset ${RESET_ARGS:-} >> "$out.meta"; fi
    sleep $SETTLE
}

read_counters() { snapshot_all "$out" $1; }

cpu_begin() { cpu_all start; }
cpu_end() { cpu_all stop "$out"; }

TRAFFIC_SUMMARY='^# (wrk2|h2load|iperf|timeout|tcpreplay) |^## backend|^Result:|pps .*errors|packets tra[a-z]*itted|'
TRAFFIC_SUMMARY+='requests in|^Requests/sec|^Transfer/sec|Socket errors|Non-2xx|^ +(50|90|99)\.000%|^ +99\.900%|'
TRAFFIC_SUMMARY+='\[SUM\]|^Actual:|^finished in|^requests:|^time for request:|^traffic:'

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

round_end() {
    check_rate "$out"
    if compgen -G "$out.lat*" >/dev/null; then gzip -f "$out".lat*; fi
    if grep -q '^traffic_error=\|^invalid=' "$out.meta"; then echo "     $(grep '^traffic_error=\|^invalid=' "$out.meta" | tr '\n' ' ')"; fi
}

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

B_NIC='cat /sys/class/net/$LB_IFACE/statistics'
C_NIC='cat /sys/class/net/$SERVER_IFACE/statistics'
B_STATS='$REPO/xdp_lb_ctl stats'
B_PROG='bpftool prog show pinned $PIN/prog'
C_UDP_IN='for i in 1 2 3; do ip netns exec server_$i nft list counter inet perf_sink udp_in; done | awk "\$1 == \"packets\" {s += \$2} END {print s}"'
C_UDP_FRAG_IN='for i in 1 2 3; do ip netns exec server_$i nft list counter inet perf_sink udp_frag_in; done | awk "\$1 == \"packets\" {s += \$2} END {print s}"'
C_REQUESTS='for i in 1 2 3; do echo b$i $(ip netns exec server_$i curl -s --max-time 1 http://$(backend_ip $i):$VPORT/nginx_status | awk "NR == 3 {print \$3}"); done'

flow_meta() { echo "profile=$1 ports=$2 threads=${3:-$PKTGEN_THREADS} src_per_thread=$SRC_PER_THREAD duration=$DURATION"; }
http_meta() { echo "http_tool=$HTTP_TOOL conns=$CONNS http_threads=$HTTP_THREADS keepalive_reqs=$KEEPALIVE_REQS http_duration=$HTTP_DURATION"; }
ports_of() { if [ $1 = new ]; then echo $NEW_PORTS; else echo $EST_PORTS; fi; }
forwarded() {
    if [ $1 = xdp ]; then cmd b "$B_STATS" | field xdp_redirect; else cmd b "$B_NIC/tx_packets"; fi
}
sent_of() { sed -n 's/^traffic:.* sent=\([0-9]*\) .*/\1/p' "$out.client"; }
delta_requests() {
    local i
    for i in 1 2 3; do delta_field "C backend $i requests" b$i "$1" "$2"; done
}

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
perf_start_check() {
    if [ -n "$PLAN" ]; then return; fi
    perf_prereq
    trap 'remote b "kill -INT \$(cat /run/perf-b.pid 2>/dev/null) 2>/dev/null; true"' EXIT
}

perf_begin() { remote b "$PERF_START_B"; }

perf_end() {
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
        }' "$out.perf.csv" | tee -a "$out.meta" | sed 's/^/  /'
}

per_unit() {
    awk -F= -v unit="$1" -v n=$2 '$1 == "b_cpu_cycles" {c = $2} $1 == "b_cpu_busy_s" {s = $2}
        END {if (n > 0) printf "  CPU ของ B ต่อ %-17s %.0f cycles  %.0f ns\n", unit, c / n, s * 1e9 / n}' "$out.meta"
}

idle_perf() {
    round_begin $1-idle $IDLE_DURATION "kind=idle $2" || return 0
    reset_b
    read_counters 0
    cpu_begin
    perf_begin
    traffic sleep $IDLE_DURATION
    perf_end
    cpu_end
    read_counters 1
    round_end
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

reset_one_core() {
    local pinned
    reset_b
    pinned=$(remote b "$ONE_CORE_B")
    echo "$pinned" >> "$out.meta"
    echo "  B 1 core: $(tr '\n' ' ' <<< "$pinned")"
    grep -q '^b_irq_cpus=0$' <<< "$pinned" && grep -Eq '^b_rps_cpus=[0,]+$' <<< "$pinned" &&
        { ! grep -q '^b_nginx' <<< "$pinned" || grep -q '^b_nginx_worker_cpus=0$' <<< "$pinned"; } ||
        { echo "B ไม่ได้ใช้ core 0 core เดียว  หยุด"; exit 1; }
}

read -r -d '' CORE0_START_B <<'EOF' || true
taskset -apc 1-3,5-7 $(pgrep -x mpstat) > /dev/null
setsid taskset -c 3 perf stat -C 0,4 -A -e cycles,ref-cycles -I 1000 -x, -o /run/perf16.csv < /dev/null > /dev/null 2>&1 &
echo $! > /run/perf16.pid
EOF
CORE0_STOP_B='pid=$(cat /run/perf16.pid); kill -INT $pid; while kill -0 $pid 2>/dev/null; do sleep 0.1; done; cat /run/perf16.csv'

core0_begin() { remote b "$CORE0_START_B"; }

core0_end() {
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
        }' "$out.perf.csv" | tee -a "$out.meta" | sed 's/^/  /'
}

per_unit0() {
    awk -F= -v unit="$1" -v n=$2 '$1 == "b_cpu0_cycles" {c = $2} $1 == "b_cpu0_busy_s" {s = $2}
        END {if (n > 0) printf "  CPU 0 ต่อ %-20s %.0f cycles  %.0f ns\n", unit, c / n, s * 1e9 / n}' "$out.meta"
}

one_core_start() {
    if [ -n "$PLAN" ]; then return; fi
    perf_prereq
    trap 'remote b "$END_B"' EXIT
}

idle_one_core() {
    round_begin $1-idle $IDLE_DURATION "kind=idle $2" || return 0
    reset_one_core
    read_counters 0
    cpu_begin
    core0_begin
    traffic sleep $IDLE_DURATION
    core0_end
    cpu_end
    read_counters 1
    round_end
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
levels() {
    local cap level
    cap=$(c0 $1 $2)
    for level in $3; do echo $level:$(( cap * level / 100 )); done
}
level_meta() { echo "level=${3%:*} rate=${3#*:} c0_scenario=$1 c0=$(c0 $1 $2) $(http_meta)"; }

use_mode() { on_b mode $1 ${2:-} >/dev/null; on_c mode $(c_mode_for $1); }

restore() {
    on_c mode guarded
    on_c quota ${QUOTA[equal]} >/dev/null
    on_c probe-drop 0
    on_b mode ${B_REST_MODE:-xdp} >/dev/null
}

check_test4() {
    need_c0 $1 web-1k
    if [ -z "$PLAN" ] && [ "$(c0_field $1 web-1k 4)" = 1 ]; then
        echo "C0 ของ $1 ใช้สายเกิน 90% (link-bound)  ลด QUOTA ของข้อ 4 ก่อน"
        exit 1
    fi
    check_variants
}

test4_levels() {
    levels $1 web-1k "$TEST4_LEVELS"
    if [ $rep -le $TEST4_SAT_REPS ]; then echo sat:sat; fi
}

variant_algo() {
    local m
    case $1 in
        xdp:wcmp)  echo wcmp 4 ;;
        xdp:lcf)   echo lcf 500 ;;
        xdp:awfd*s) m=${1#xdp:awfd}; echo awfd ${m%s} 500 $TEST4_AWFD_TUNE ;;
        xdp:awfd*) echo awfd ${1#xdp:awfd} 500 ;;
        ipvs:wlc|nginx:least_conn|haproxy:leastconn) echo ${1#*:} ${QUOTA[$2]//%/} ;;
        *)         echo ${1#*:} ;;
    esac
}
check_variants() {
    local kinds
    kinds=$(for variant in $TEST4_VARIANTS; do [ ${variant%%:*} = xdp ] && echo xdp || echo other; done | sort -u)
    [ $(wc -l <<< "$kinds") = 1 ] || { echo "TEST4_VARIANTS ผสม xdp กับ LB อื่น  แยกรันเป็นคนละครั้ง"; exit 1; }
    [ "$kinds" = xdp ] || B_REST_MODE=${B_REST_MODE:-none}
}

overhead() {
    read -r OVERHEAD_MS GAP_ROUNDS <<< "$(cat "$RUN_DIR"/*.meta 2>/dev/null |
        awk -F= '$1 == "gap_ms" {sum += $2; n++} END {if (n) printf "%d %d", sum / n, n}')"
    if [ -n "$OVERHEAD" ]; then OVERHEAD_MS=$(awk -v s=$OVERHEAD 'BEGIN {printf "%d", s * 1000}') GAP_ROUNDS=""; fi
    OVERHEAD_MS=${OVERHEAD_MS:-5000}
}
hours() { awk -v ms=$1 'BEGIN {printf "%.2f", ms / 3600000}'; }

plan_one() {
    local TEST=$1
    PLAN_ROUNDS=0 PLAN_LEFT=0 PLAN_MS=0 PLAN_LEFT_MS=0
    t${TEST/./_} >/dev/null
    echo $TEST $PLAN_ROUNDS $PLAN_LEFT $PLAN_MS $PLAN_LEFT_MS
}
plan_of() { ( PLAN=1; for id in "$@"; do plan_one $id; done ) }

plan() {
    local id rounds left ms left_ms notes sum=(0 0 0 0)
    local -A RAN=()
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

eta() {
    local rounds left ms left_ms
    overhead
    read -r _ rounds left ms left_ms <<< "$(plan_of $TEST 2>/dev/null)"
    echo "   ${rounds:-0} รอบ (ยังไม่เสร็จ ${left:-0})  ประมาณ $(( ${left_ms:-0} / 60000 )) นาที" \
         "เสร็จราว $(date -d "+$(( ${left_ms:-0} / 1000 )) seconds" +%H:%M)"
}

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
            PMTU_PPS TEST4_VARIANTS TEST4_LEVELS TEST4_SAT_REPS QUOTA TEST4_SCENARIOS VIP_MTU
    } >> "$RUN_DIR/env-a.txt"
    { echo "=== $(date '+%F %T')"; on_b env; } >> "$RUN_DIR/env-b.txt"
    { echo "=== $(date '+%F %T')"; on_c env; } >> "$RUN_DIR/env-c.txt"
    KEEPALIVE_REQS=$(sed -n 's/^nginx_keepalive_requests=//p' "$RUN_DIR/env-c.txt" | tail -1)
    SEQ=$(cat "$RUN_DIR"/*.meta 2>/dev/null | sed -n 's/^seq=//p' | sort -n | tail -1)
    SEQ=${SEQ:-0}
    overhead
    {
        echo "== ค่าจริง  A $CLIENT_IFACE $CLIENT_IP  B $(remote b 'echo $LB_IFACE') $LB_IP $LB_MAC" \
             " C $(remote c 'echo $SERVER_IFACE') $SERVER_IP $SERVER_MAC"
        echo "   VIP $VIP  backend $(backend_ip 1) $(backend_ip 2) $(backend_ip 3)"
    } | tee -a "$RUN_DIR/env-a.txt"
}

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
