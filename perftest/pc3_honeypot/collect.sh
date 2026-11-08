#!/bin/bash
# ============================================================
#  collect.sh (PC3 honeypot) — ใช้คู่กับ g_redirect ที่ PC2 (automated via ssh)
#  g_redirect เรียก:  ./collect.sh <label> <duration_s>
#  อ่านชื่อการ์ดจาก PC3_IFACE ใน ../common.conf (ไม่พึ่ง lib.sh)
#  นับ rx จาก /proc/net/dev (ระดับการ์ด ก่อน IP stack เช็ก dst)
# ============================================================
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="$HERE/../common.conf"; [ -f "$CONF" ] && source "$CONF"
IF="${PC3_IFACE:?ตั้ง PC3_IFACE ใน common.conf เป็นการ์ด data ของ PC3 ก่อน}"
LABEL="${1:-redirect}"; DUR="${2:-60}"
OUT="$HERE/results_pc3"; mkdir -p "$OUT"
TS=$(date +%Y%m%d_%H%M%S); LOG="$OUT/${TS}_${LABEL}.txt"

snap(){ awk -v i="$IF:" '$1==i{print $3" "$2}' /proc/net/dev; }

echo "[PC3] นับ rx ของ $IF เป็นเวลา ${DUR}s (label=$LABEL)"
read -r P0 B0 < <(snap)
[ -z "${P0:-}" ] && { echo "[PC3] ไม่พบการ์ด '$IF' ใน /proc/net/dev — เช็ก: ip -br link"; exit 1; }
T0=$(date +%s%N)
sleep "$DUR"
read -r P1 B1 < <(snap); T1=$(date +%s%N)

DT=$(awk -v a="$T0" -v b="$T1" 'BEGIN{printf "%.3f",(b-a)/1e9}')
DP=$((P1-P0)); DB=$((B1-B0))
PPS=$(awk -v p="$DP" -v d="$DT" 'BEGIN{printf "%d",p/d}')
MBPS=$(awk -v b="$DB" -v d="$DT" 'BEGIN{printf "%.1f",b*8/d/1e6}')

{
  echo "label=$LABEL iface=$IF duration_s=$DT"
  echo "rx_pkts_delta=$DP rx_bytes_delta=$DB rx_pps=$PPS rx_mbps=$MBPS"
  echo "note: เทียบ rx_pps กับ xdp_redirect ที่ PC2 ควรใกล้กัน"
} | tee "$LOG"
echo "[PC3] เก็บผล -> $LOG"