#!/bin/bash
# ============================================================
#  load.sh (PC1 Ubuntu) — ตัว generate ทราฟฟิกปริมาณสูงเข้า PC2
#  ใช้ kernel pktgen (UDP) เป็นหลัก เพราะยิงเต็ม 1G ได้
#  ทุกโหมด print บอกว่ากำลังทำอะไร และสรุปจำนวน packet ที่ส่งจริง
#
#  ใช้ (ต้อง sudo):
#    sudo ./load.sh udp --pct 50 --size 64 --dur 60 --src single
#    sudo ./load.sh udp --pct 90 --size 64 --dur 60 --src random --nsrc 60000
#    sudo ./load.sh udp --pps 5000 --size 64 --dur 60 --src portrand   # IP เดียว สุ่ม port
#    sudo ./load.sh syn  --pps 50000 --dur 30             # ใช้ hping3
#    sudo ./load.sh icmp --pps 50000 --dur 30
#  --src: single (IP เดียว clone เร็ว) | random (spoofed หลาย IP, ใช้ --nsrc) | portrand (IP เดียว random port)
#  ผลสรุป (packet ที่ส่ง) เก็บที่ ./results_pc1/<ts>_<mode>.txt
# ============================================================
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="$HERE/../common.conf"; [ -f "$CONF" ] || { echo "ไม่พบ common.conf"; exit 1; }
# shellcheck disable=SC1090
source "$CONF"
OUT="$HERE/results_pc1"; mkdir -p "$OUT"
say(){ echo -e "[PC1] $*"; }

[ "$(id -u)" -eq 0 ] || { echo "ต้องรันด้วย sudo"; exit 1; }
MODE="${1:?ระบุโหมด: udp|syn|icmp}"; shift

PCT=""; SIZE=64; DUR=30; SRC="single"; PPS=""; NSRC=""
while [ $# -gt 0 ]; do case "$1" in
    --pct)  PCT="$2"; shift 2;;
    --pps)  PPS="$2"; shift 2;;
    --size) SIZE="$2"; shift 2;;
    --dur)  DUR="$2"; shift 2;;
    --src)  SRC="$2"; shift 2;;   # single | random | portrand
    --nsrc) NSRC="$2"; shift 2;;  # จำนวน source IP ที่จะสุ่ม (เฉพาะ --src random)
    *) echo "ไม่รู้จัก option: $1"; exit 1;;
esac; done
: "${NSRC:=${ATK_SRC_COUNT:-1000}}"

# เตือนถ้า size ใหญ่เกิน frame มาตรฐาน (payload > 1500 MTU จะโดน drop เป็น oversize)
if [ "$SIZE" -gt 1514 ]; then
    say "เตือน: size=$SIZE > 1514 (payload เกิน 1500 MTU) จะถูก drop เป็น oversize — ใช้ 1514 แทนถ้าไม่ได้เปิด jumbo"
fi

TS=$(date +%Y%m%d_%H%M%S)
LOG="$OUT/${TS}_${MODE}.txt"

# แปลง IP <-> int สำหรับสร้างช่วง source IP ข้าม octet
ip2int(){ local a b c d; IFS=. read -r a b c d <<<"$1"; echo $(( (a<<24)+(b<<16)+(c<<8)+d )); }
int2ip(){ local n=$1; echo "$(( (n>>24)&255 )).$(( (n>>16)&255 )).$(( (n>>8)&255 )).$(( n&255 ))"; }

# คำนวณ pps เป้าหมายจาก % ของ line rate 1G (รวม 20B IFG+preamble ต่อ frame)
linerate_pps() { awk -v s="$1" 'BEGIN{printf "%d", 1e9/((s+20)*8)}'; }
if [ -n "$PCT" ] && [ -z "$PPS" ]; then
    LR=$(linerate_pps "$SIZE"); PPS=$(awk -v l="$LR" -v p="$PCT" 'BEGIN{printf "%d", l*p/100}')
fi
: "${PPS:=100000}"

{
echo "mode=$MODE size=$SIZE dur=$DUR src=$SRC target_pps=$PPS pct=${PCT:-NA}"
echo "dst_ip=$PC2_SVC_IP dst_mac=$PC2_IN_MAC iface=$PC1_IFACE start=$(date -Iseconds)"
} | tee "$LOG"

# ---------- pktgen (UDP) ----------
pg(){ echo "$1" > "$2"; }
run_pktgen() {
    modprobe pktgen 2>/dev/null || { say "โหลด pktgen ไม่ได้ (apt install linux-modules-extra-\$(uname -r))"; exit 1; }
    local dev="$PC1_IFACE@0" thr=/proc/net/pktgen/kpktgend_0
    local count=$(( PPS * DUR ))
    say "ตั้งค่า pktgen: dev=$dev count=$count ($PPS pps x ${DUR}s) size=$SIZE"
    # สำคัญ: หยุด + ล้าง device ของ "ทุก" thread ก่อน
    # ไม่งั้น device ค้างบน thread อื่นจะถูก start พร้อมกัน (pgctrl start เริ่มทุก thread) → ทราฟฟิกปน
    echo stop > /proc/net/pktgen/pgctrl 2>/dev/null || true
    local t
    for t in /proc/net/pktgen/kpktgend_*; do echo "rem_device_all" > "$t" 2>/dev/null || true; done
    pg "add_device $PC1_IFACE@0" "$thr"
    local d=/proc/net/pktgen/$PC1_IFACE@0
    pg "count $count"        "$d"
    pg "pkt_size $SIZE"      "$d"
    pg "delay 0"             "$d"
    pg "ratep $PPS"          "$d"
    pg "dst $PC2_SVC_IP"     "$d"
    pg "dst_mac $PC2_IN_MAC" "$d"
    pg "udp_dst_min 80"      "$d"
    pg "udp_dst_max 80"      "$d"
    local clone=1000    # single: clone skb ยิงเร็วขึ้นมาก (เข้าใกล้ line rate)
    case "$SRC" in
        random)
            clone=0     # สุ่มค่าในแต่ละ packet ไม่ได้ ถ้า clone
            # ช่วง source IP ปลอมข้าม octet: ATK_SRC_NET .. +NSRC (ได้ IP เยอะจริง)
            local base smin smax
            base=$(ip2int "$ATK_SRC_NET")
            smin=$(int2ip $(( base + 1 )))
            smax=$(int2ip $(( base + NSRC )))
            pg "flag IPSRC_RND" "$d"
            pg "src_min $smin"  "$d"
            pg "src_max $smax"  "$d"
            pg "flag UDPSRC_RND" "$d"
            pg "udp_src_min 1024" "$d"; pg "udp_src_max 65000" "$d"
            say "source: random $smin..$smax (~$NSRC IP, spoofed)"
            ;;
        portrand)
            clone=0
            # IP เดียวคงที่ (ใช้ ATK_SRC_NET) แต่สุ่ม source port → RSS กระจายหลาย core
            local fixip="$ATK_SRC_NET"
            pg "src_min $fixip" "$d"; pg "src_max $fixip" "$d"
            pg "flag UDPSRC_RND" "$d"
            pg "udp_src_min 1024" "$d"; pg "udp_src_max 65000" "$d"
            say "source: IP เดียว $fixip + random port (ทดสอบ race ข้าม core)"
            ;;
        *)  # single
            pg "src_min $PC1_IP" "$d"; pg "src_max $PC1_IP" "$d"
            say "source: single $PC1_IP (clone_skb=$clone)"
            ;;
    esac
    pg "clone_skb $clone" "$d"
    say "เริ่มยิง UDP flood ${DUR}s ... (รอจนจบ)"
    pg "start" /proc/net/pktgen/pgctrl
    say "ยิงจบ — ผลจาก pktgen:"
    grep -E "pkts-sofar|errors|rate:" "$d" | tee -a "$LOG"
}

# ---------- hping3 (SYN / ICMP) ----------
run_hping() {
    command -v hping3 >/dev/null || { say "ไม่มี hping3 (apt install hping3)"; exit 1; }
    local args=(--flood -d $((SIZE>40?SIZE-40:0)) -p "$HTTP_PORT")
    [ "$SRC" = "random" ] && args+=(--rand-source)
    case "$MODE" in
        syn)  args=(-S "${args[@]}");;
        icmp) args=(-1 --flood);  [ "$SRC" = "random" ] && args+=(--rand-source);;
    esac
    say "เริ่ม $MODE flood ด้วย hping3 ${DUR}s (flood mode = เร็วสุดที่เครื่องไหว)"
    say "หมายเหตุ: hping3 ไม่คุม pps ตรง ๆ — ใช้สำหรับทดสอบ 'ฟังก์ชันถูกต้อง' ไม่ใช่วัด throughput"
    timeout "$DUR" hping3 "${args[@]}" "$PC2_SVC_IP" 2>&1 | tee -a "$LOG" || true
    say "$MODE flood จบ"
}

case "$MODE" in
    udp)  run_pktgen;;
    syn|icmp) run_hping;;
    *) echo "โหมดไม่ถูกต้อง"; exit 1;;
esac
echo "end=$(date -Iseconds)" >> "$LOG"
say "บันทึกผลฝั่ง PC1 -> $LOG"