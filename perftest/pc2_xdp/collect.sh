#!/bin/bash
# ============================================================
#  collect.sh — เก็บผล 1 หน้าต่างวัดบน PC2 (ตัว DUT)
#  เรียกตอน "load กำลังวิ่งอยู่แล้ว" — มันจะ snapshot ก่อน/หลัง
#  แล้วคำนวณ delta เขียนลง CSV + เก็บไฟล์ดิบไว้ในโฟลเดอร์ของรอบนั้น
#
#  ใช้:
#    sudo ./collect.sh <scenario> <variant> <rep> [duration_s] [key=val ...]
#  ตัวอย่าง:
#    sudo ./collect.sh throughput xdp_native_64B 1 60 rate_pct=50 pkt=64
# ============================================================
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"; load_conf

SCN="${1:?ต้องระบุ scenario}"; VAR="${2:?ต้องระบุ variant}"; REP="${3:?ต้องระบุ rep}"
DUR="${4:-$DURATION_S}"; shift $(( $# >= 4 ? 4 : 3 )); EXTRA_KV=("$@")

RUNDIR="$RESULTS_ROOT/$SCN/${VAR}_rep${REP}"
mkdir -p "$RUNDIR"
SUMMARY="$RESULTS_ROOT/summary.csv"

step "เคส: scenario=$SCN variant=$VAR rep=$REP  (วัด ${DUR}s, warmup ${WARMUP_S}s)"
[ ${#EXTRA_KV[@]} -gt 0 ] && echo "    params: ${EXTRA_KV[*]}"

# เขียน metadata ของรอบ
{
    echo "scenario=$SCN"; echo "variant=$VAR"; echo "rep=$REP"
    echo "duration_s=$DUR"; echo "start_wall=$(date -Iseconds)"
    echo "kernel=$(uname -r)"; echo "host=$(hostname)"
    for kv in "${EXTRA_KV[@]}"; do echo "param_$kv"; done
    drv=$(ethtool -i "$PC2_IN_IF" 2>/dev/null | awk '/^driver:/{print $2}'); echo "in_driver=$drv"
    echo "xdp_mode=$(ip -d link show "$PC2_IN_IF" 2>/dev/null | grep -oE 'xdp(generic|drv|)?' | head -1)"
} > "$RUNDIR/meta.txt"

bpf_stats_on

step "warmup ${WARMUP_S}s (ให้ load เข้าสู่สภาวะคงที่ก่อนเริ่มนับ)"
sleep "$WARMUP_S"

step "snapshot ตัวนับ ณ T0"
snapshot_counters "$RUNDIR/t0.kv"

step "เริ่ม sampler (mpstat/softirq) และวัด ${DUR}s ..."
start_samplers "$RUNDIR" "$DUR"
# นับ blocked กลางทาง (ช่วยดูว่าบล็อกเกิดเมื่อไร)
( t=0; while [ "$t" -lt "$DUR" ]; do
    echo "$(date +%s%N) blocked=$(count_blocked)"; sleep 2; t=$((t+2))
  done ) > "$RUNDIR/blocked_timeline.txt" 2>/dev/null &
BLK_PID=$!

# แสดง progress เป็นวินาที
for ((s=1; s<=DUR; s++)); do
    printf "\r    วัดอยู่: %d/%ds" "$s" "$DUR"; sleep 1
done; printf "\n"

kill "$BLK_PID" 2>/dev/null
stop_samplers "$RUNDIR"

step "snapshot ตัวนับ ณ T1"
snapshot_counters "$RUNDIR/t1.kv"

step "คำนวณ delta และสรุปผล"
# คำนวณ delta ด้วย python (กันเลขหาย/field ไม่ครบ)
python3 - "$RUNDIR/t0.kv" "$RUNDIR/t1.kv" "$DUR" > "$RUNDIR/delta.kv" <<'PY'
import sys
def load(f):
    d={}
    for ln in open(f):
        ln=ln.strip()
        if not ln or ln.startswith("#"):
            if ln.startswith("# ts_ns="): d["_ts_ns"]=int(ln.split("=")[1])
            continue
        if "=" in ln:
            k,v=ln.split("=",1)
            try: d[k]=int(v)
            except ValueError:
                try: d[k]=float(v)
                except ValueError: d[k]=v
    return d
t0,t1,dur=load(sys.argv[1]),load(sys.argv[2]),float(sys.argv[3])
real_dt=(t1.get("_ts_ns",0)-t0.get("_ts_ns",0))/1e9 or dur
out={}
for k in set(t0)|set(t1):
    if k.startswith("_"): continue
    a,b=t0.get(k),t1.get(k)
    if isinstance(a,(int,float)) and isinstance(b,(int,float)):
        out[k+"_delta"]=b-a
out["measure_dt_s"]=round(real_dt,3)
# ns ต่อ packet ของ ratelimit และ main (ถ้า bpf_stats เปิด)
for pre in ("main","rl"):
    dn=out.get(f"{pre}_run_time_ns_delta",0); dc=out.get(f"{pre}_run_cnt_delta",0)
    out[f"{pre}_ns_per_pkt"]=round(dn/dc,2) if dc else 0
    out[f"{pre}_pps"]=round(dc/real_dt) if real_dt else 0
for k in sorted(out): print(f"{k}={out[k]}")
PY

# ดึงค่าหลัก ๆ มาทำ CSV
get() { awk -F= -v k="$1" '$1==k{print $2}' "$RUNDIR/delta.kv"; }
CPU_BUSY=$(mpstat_busy_avg "$RUNDIR")
RL_NSPP=$(get rl_ns_per_pkt); RL_PPS=$(get rl_pps)
MAIN_NSPP=$(get main_ns_per_pkt)
RL_CNT=$(get rl_run_cnt_delta)
IN_PKTS=$(get in_rx_pkts_delta)
# xdp counters (อาจไม่มีในบาง driver)
# pass/drop/redirect: ใช้ per-CPU counter ในโปรแกรมก่อน (แม่นทุก driver) ถ้าไม่มีค่อย fallback ไป ethtool
XDP_PASS=$(get rl_cnt_pass_delta);     [ -z "$XDP_PASS" ]  && XDP_PASS=$(get in_rx_xdp_pass_delta)
XDP_DROP=$(get rl_cnt_drop_delta);     [ -z "$XDP_DROP" ]  && XDP_DROP=$(get in_rx_xdp_drop_delta)
XDP_REDIR=$(get rl_cnt_redirect_delta);[ -z "$XDP_REDIR" ] && XDP_REDIR=$(get in_rx_xdp_redirect_delta)
OUT_TX=$(get out_tx_pkts_delta)
BLK_MAX=$(awk '{for(i=1;i<=NF;i++) if($i~/blocked=/){split($i,a,"=");if(a[2]>m)m=a[2]}} END{print m+0}' "$RUNDIR/blocked_timeline.txt" 2>/dev/null)

# header (เขียนครั้งแรกครั้งเดียว)
if [ ! -f "$SUMMARY" ]; then
    echo "scenario,variant,rep,duration_s,params,in_driver,in_rx_pkts,rl_run_cnt,rl_pps,rl_ns_per_pkt,main_ns_per_pkt,xdp_pass,xdp_drop,xdp_redirect,out_tx_pkts,cpu_busy_pct,blocked_max,rundir" > "$SUMMARY"
fi
printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$SCN" "$VAR" "$REP" "$DUR" "$(IFS=';'; echo "${EXTRA_KV[*]}")" "$(get in_driver)" \
    "${IN_PKTS:-}" "${RL_CNT:-}" "${RL_PPS:-}" "${RL_NSPP:-}" "${MAIN_NSPP:-}" \
    "${XDP_PASS:-}" "${XDP_DROP:-}" "${XDP_REDIR:-}" "${OUT_TX:-}" \
    "${CPU_BUSY:-}" "${BLK_MAX:-}" "$RUNDIR" >> "$SUMMARY"

bpf_stats_off
ok "เสร็จ 1 รอบ -> $RUNDIR"
echo "    rl: ${RL_PPS:-?} pps, ${RL_NSPP:-?} ns/pkt | CPU busy ${CPU_BUSY:-?}% | drop ${XDP_DROP:-?} redirect ${XDP_REDIR:-?} | blocked_max ${BLK_MAX:-?}"
echo "    บันทึกลง: $SUMMARY"
