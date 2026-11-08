#!/bin/bash
# ============================================================
#  lib.sh — ฟังก์ชันร่วมสำหรับ script ฝั่ง PC2 (เครื่อง XDP)
#  ไม่รันตรง ๆ — ให้ script อื่น source เข้าไป
# ============================================================

# ---------- สี + การ print บอกสถานะ ----------
if [ -t 1 ]; then C_B="\033[1;36m"; C_G="\033[1;32m"; C_Y="\033[1;33m"; C_R="\033[1;31m"; C_0="\033[0m"
else C_B=""; C_G=""; C_Y=""; C_R=""; C_0=""; fi

step() { echo -e "${C_B}[*]${C_0} $*"; }
ok()   { echo -e "${C_G}[+]${C_0} $*"; }
warn() { echo -e "${C_Y}[!]${C_0} $*"; }
err()  { echo -e "${C_R}[x]${C_0} $*" >&2; }
hr()   { echo "------------------------------------------------------------"; }

# ---------- โหลด config ----------
# หา common.conf จากโฟลเดอร์แม่ของ script ที่เรียก
load_conf() {
    local here; here="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
    local conf="$here/../common.conf"
    [ -f "$conf" ] || { err "ไม่พบ common.conf ที่ $conf"; exit 1; }
    # shellcheck disable=SC1090
    source "$conf"
    CONF_DIR="$(cd "$(dirname "$conf")" && pwd)"
    PROJECT_DIR="$(cd "$CONF_DIR/.." && pwd)"   # รากของ XDP-Firewall-xdp-rl
    : "${RESULTS_ROOT:=./results}"
    # ทำ RESULTS_ROOT ให้เป็น absolute อิงจากตำแหน่ง common.conf
    case "$RESULTS_ROOT" in
        /*) : ;;
        *)  RESULTS_ROOT="$CONF_DIR/${RESULTS_ROOT#./}" ;;
    esac
    mkdir -p "$RESULTS_ROOT"
}

# ---------- ตรวจว่ามีเครื่องมือครบไหม ----------
need() {
    local miss=0 t
    for t in "$@"; do
        command -v "$t" >/dev/null 2>&1 || { warn "ไม่พบคำสั่ง: $t"; miss=1; }
    done
    return $miss
}

# ---------- หา pin path ของ ratelimit (จาก setup.sh) ----------
# ratelimit pin อยู่ที่ /sys/fs/bpf/ddos (slot 0 ใน STAGES)
RL_PIN="${RL_PIN:-/sys/fs/bpf/ddos}"
MAIN_PIN="${MAIN_PIN:-/sys/fs/bpf/xdp_main}"

xdp_loaded() { [ -e "$RL_PIN/prog" ]; }

# ---------- เปิด/ปิด bpf runtime stats (ns ต่อ packet) ----------
bpf_stats_on()  { sysctl -qw kernel.bpf_stats_enabled=1 2>/dev/null || \
                  echo 1 > /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || \
                  warn "เปิด bpf_stats_enabled ไม่ได้ (ns/pkt จะว่าง)"; }
bpf_stats_off() { sysctl -qw kernel.bpf_stats_enabled=0 2>/dev/null || \
                  echo 0 > /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || true; }

# อ่าน run_time_ns และ run_cnt ของ prog ที่ pin ไว้ -> "ns_total cnt"
# ใช้ bpftool -j; ถ้าไม่มี field (stats ปิด) คืน "0 0"
prog_stats() {   # prog_stats <pinned prog path>
    local p="$1"
    [ -e "$p" ] || { echo "0 0"; return; }
    bpftool -j prog show pinned "$p" 2>/dev/null | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: print("0 0"); sys.exit()
print(d.get("run_time_ns",0), d.get("run_cnt",0))
' 2>/dev/null || echo "0 0"
}

# ---------- อ่านตัวนับ xdp จาก ethtool -S (ขึ้นกับ driver) ----------
# รวมทุก queue ของ counter ที่ชื่อมีคำว่า xdp + drop/pass/redirect/tx
# คืนเป็น key=value ทีละบรรทัด (ยังไม่ delta)
ethtool_xdp() {   # ethtool_xdp <iface>
    ethtool -S "$1" 2>/dev/null | awk '
      /xdp/ && /:/ {
        gsub(/^[ \t]+/,""); n=$1; sub(/:.*/,"",n);
        v=$NF; gsub(/[^0-9]/,"",v);
        if (v!="") sum[n]+=v
      }
      END { for (k in sum) print k"="sum[k] }
    '
}

# ---------- snapshot ตัวนับทั้งหมด ณ เวลาหนึ่ง ----------
# เขียนไฟล์ snapshot (key=value) ไว้ที่ $1
snapshot_counters() {   # snapshot_counters <outfile>
    local out="$1"
    {
        echo "# ts_ns=$(date +%s%N)"
        local ps
        ps=$(prog_stats "$MAIN_PIN/prog"); echo "main_run_time_ns=${ps% *}"; echo "main_run_cnt=${ps#* }"
        ps=$(prog_stats "$RL_PIN/prog");   echo "rl_run_time_ns=${ps% *}";   echo "rl_run_cnt=${ps#* }"
        # ethtool xdp counters (prefix ด้วยชื่อ iface)
        local kv
        while IFS= read -r kv; do [ -n "$kv" ] && echo "in_$kv"; done < <(ethtool_xdp "$PC2_IN_IF")
        while IFS= read -r kv; do [ -n "$kv" ] && echo "out_$kv"; done < <(ethtool_xdp "$PC2_OUT_IF")
        # /proc/net/dev ของ IN/OUT
        awk -v i="$PC2_IN_IF"  '$1==i":"{gsub(":","",$1); print "in_rx_bytes="$2; print "in_rx_pkts="$3; print "in_rx_drop="$5}' /proc/net/dev
        awk -v o="$PC2_OUT_IF" '$1==o":"{gsub(":","",$1); print "out_tx_bytes="$10; print "out_tx_pkts="$11}' /proc/net/dev
        # per-CPU counter จากตัวโปรแกรม (pass/drop/redirect) — แม่นกว่า ethtool
        read_rl_counts
    } > "$out"
}

# ---------- อ่าน per-CPU counter rl_counts (รวมทุก CPU) ----------
# พิมพ์ rl_cnt_pass / rl_cnt_drop / rl_cnt_redirect (ไม่มี map ก็ไม่พิมพ์)
read_rl_counts() {
    [ -e "$RL_PIN/rl_counts" ] || return 0
    bpftool -j map dump pinned "$RL_PIN/rl_counts" 2>/dev/null | python3 -c '
import json,sys
try: rows=json.load(sys.stdin)
except Exception: sys.exit()
names={0:"pass",1:"drop",2:"redirect"}
def tohex_int(x):
    if isinstance(x,list): return int.from_bytes(bytes(int(b,16) for b in x),"little")
    return int(x)
for r in rows:
    k=r.get("key")
    k=tohex_int(k) if not isinstance(k,int) else k
    tot=0
    # percpu: อาจเป็น "values":[{cpu,value}], หรือ "value" เดี่ยว
    if "values" in r:
        for pc in r["values"]:
            tot+=tohex_int(pc.get("value",0))
    else:
        tot+=tohex_int(r.get("value",0))
    if k in names: print("rl_cnt_%s=%d"%(names[k],tot))
' 2>/dev/null || true
}

# ---------- นับ entry ที่ "ถูกบล็อก" ใน rate_limit_map ----------
# (blocked_until != 0 และยังไม่หมดเวลา) — ใช้ตรวจความแม่นยำ
count_blocked() {
    [ -e "$RL_PIN/rate_limit_map" ] || { echo 0; return; }
    bpftool -j map dump pinned "$RL_PIN/rate_limit_map" 2>/dev/null | python3 -c '
import json,sys,struct
try: rows=json.load(sys.stdin)
except Exception: print(0); sys.exit()
def b2(x):  # x = list of "0xNN"
    return bytes(int(v,16) for v in x)
n=0
for r in rows:
    v=b2(r.get("value",[]))
    if len(v)>=16:
        blocked_until=struct.unpack_from("<Q",v,8)[0]
        if blocked_until: n+=1
print(n)
' 2>/dev/null || echo 0
}

# ---------- เริ่ม/หยุด sampler พื้นหลัง (mpstat) ----------
# start_samplers <rundir> <dur>  -> เขียน PID ไว้ใน $rundir/.samplers
# สำคัญ: ต้องให้ mpstat จบเองด้วย count=<dur> ไม่งั้นถ้าโดน kill มันจะไม่พิมพ์บรรทัด Average
start_samplers() {
    local rd="$1" dur="${2:-60}"; : > "$rd/.samplers"
    if command -v mpstat >/dev/null 2>&1; then
        # LC_ALL=C กันทศนิยมเป็น comma; count=dur ให้ mpstat จบเองพร้อมบรรทัด Average
        ( LC_ALL=C mpstat -P ALL 1 "$dur" > "$rd/mpstat.txt" 2>/dev/null ) & echo $! >> "$rd/.samplers"
    else
        warn "ไม่มี mpstat (ลง sysstat) — ข้ามการเก็บ CPU ต่อ core"
    fi
    # เก็บ softirq รวมจาก /proc/stat ทุกวินาที (เบา ๆ เป็น backup)
    ( while :; do echo "$(date +%s%N) $(awk '/^softirq/{print $2}' /proc/stat)"; sleep 1; done \
        > "$rd/softirq.txt" 2>/dev/null ) & echo $! >> "$rd/.samplers"
}
stop_samplers() {
    local rd="$1"; [ -f "$rd/.samplers" ] || return 0
    local pid
    while read -r pid; do kill "$pid" 2>/dev/null; done < "$rd/.samplers"
    rm -f "$rd/.samplers"
}

# ---------- สรุป CPU idle เฉลี่ยจาก mpstat (คืน %busy เฉลี่ยทุก core) ----------
# ใช้บรรทัด Average: all ถ้ามี ไม่มีก็เฉลี่ยจากบรรทัด interval "all" เอง (เผื่อ mpstat ถูก kill)
mpstat_busy_avg() {   # mpstat_busy_avg <rundir>
    local f="$1/mpstat.txt"; [ -f "$f" ] || { echo ""; return; }
    if [ "${PIN_1CORE:-0}" = "1" ]; then
        # โหมด 1 core: คืน %busy ของ core ที่ยุ่งสุด (= core ที่ถูก pin) — 100% คือ core เต็ม
        awk '
          $1=="Average:" && $2 ~ /^[0-9]+$/ { b=100-$NF; if(b>mx)mx=b; have=1 }
          $2 ~ /^[0-9]+$/ && $1 ~ /:/       { b=100-$NF; if(b>mi)mi=b; havei=1 }
          END {
            if (have)      printf "%.1f", mx
            else if (havei) printf "%.1f", mi
            else            print ""
          }
        ' "$f"
    else
        awk '
          $1=="Average:" && $2=="all" { avg=100-$NF; haveavg=1; next }
          $2=="all" && $1 ~ /:/       { sum+=100-$NF; n++ }
          END {
            if (haveavg)   printf "%.1f", avg
            else if (n>0)  printf "%.1f", sum/n
            else           print ""
          }
        ' "$f"
    fi
}

# ---------- สั่งงานข้ามเครื่อง (ssh หรือ manual) ----------
# remote_run <host-label> <ssh-target> <cmd...>
# ORCH_MODE=ssh   : ssh ไปรันจริง
# ORCH_MODE=manual: พิมพ์คำสั่งให้ไปรันเอง แล้ว return ทันที (ใช้คู่กับ wait_enter)
remote_run() {
    local label="$1" target="$2"; shift 2
    if [ "$ORCH_MODE" = "ssh" ]; then
        step "[$label] ssh: $*"
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$target" "cd $REMOTE_PERFTEST_DIR && $*"
    else
        echo
        warn "[$label] ไปรันคำสั่งนี้ที่เครื่อง $label:"
        echo "    cd <perftest> && $*"
    fi
}
wait_enter() { [ "$ORCH_MODE" = "manual" ] && { read -rp ">> กด Enter เมื่อรันคำสั่งข้างบนเรียบร้อย/พร้อมไปต่อ... " _; }; return 0; }
