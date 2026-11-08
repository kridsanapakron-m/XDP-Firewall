#!/bin/bash
# ============================================================
#  micro_bench.sh — วัด ns/pkt ของ ratelimit แบบไม่ต้องมีการ์ด/ไม่ต้องมี PC อื่น
#  ใช้ BPF_PROG_TEST_RUN (bpftool prog run ... repeat N) ป้อน packet เดิมซ้ำ ๆ
#  เหมาะกับ "เทียบโค้ดแต่ละแบบ" (เช่น ++ กับ atomic, fixed window กับ token bucket)
#  ทำบน PC2 เครื่องเดียวได้เลย เป็นด่านแรกก่อนไป full test
#
#  ใช้:  sudo ./micro_bench.sh [repeat]     (default 10,000,000)
# ============================================================
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"; load_conf
[ "$(id -u)" -eq 0 ] || { err "ต้องรันด้วย sudo"; exit 1; }
need bpftool python3 || exit 1
xdp_loaded || { err "ยังไม่ได้โหลด ratelimit ที่ $RL_PIN (รัน setup.sh ก่อน)"; exit 1; }

REPEAT="${1:-10000000}"
OUTDIR="$RESULTS_ROOT/micro"; mkdir -p "$OUTDIR"
PKT="$OUTDIR/pkt_tcp_syn.bin"; OUTBIN="$OUTDIR/out.bin"

step "สร้าง test packet (TCP SYN 1.1.1.1 -> $PC2_SVC_IP:80) ขนาด 54B"
python3 - "$PKT" "$PC2_SVC_IP" <<'PY'
import sys, socket, struct
path, dst = sys.argv[1], sys.argv[2]
eth = bytes(12) + b"\x08\x00"
ip = struct.pack("!BBHHHBBH4s4s", 0x45,0,40,0,0,64,6,0,
                 socket.inet_aton("1.1.1.1"), socket.inet_aton(dst))
tcp = struct.pack("!HHIIBBHHH", 40000,80,0,0,0x50,0x02,0,0,0)
open(path,"wb").write(eth+ip+tcp)
PY

step "ตั้ง threshold สูงมาก (วัดเฉพาะเส้นทาง pass ต่อ packet ไม่ให้บล็อก)"
"$HERE/rlconf.py" set --proto tcp --threshold 2000000000 --window-ms 100000 --block-s 1 --action drop >/dev/null
"$HERE/rlconf.py" clear >/dev/null 2>&1 || true

# ถ้าเป็นเวอร์ชัน chain (มี jmp_table ใน pin dir) ให้ตัด stage ถัดไปชั่วคราว
# ไม่งั้น test_run จะ tail call ไป firewall ที่ไม่มี metadata แล้ว drop (วัดผิดตัว)
# เวอร์ชัน standalone จะไม่มี jmp_table — ข้ามส่วนนี้ไปเอง
JMP="$RL_PIN/jmp_table"; SAVED=""
if [ -e "$JMP" ]; then
    warn "ตรวจพบ jmp_table (เวอร์ชัน chain) — ตัด stage ถัดไปชั่วคราวเพื่อวัดเฉพาะ ratelimit"
    SAVED=$(bpftool -j map dump pinned "$JMP" 2>/dev/null)
    for k in 1 2 3 4 5 6 7; do
        bpftool map delete pinned "$JMP" key "$k" 0 0 0 2>/dev/null || true
    done
fi
restore_jmp() {
    [ -n "$SAVED" ] || return 0
    # PROG_ARRAY ต้องใส่คืนด้วย prog id (ค่าใน dump คือ id ของ prog ที่ pin อยู่)
    echo "$SAVED" | python3 -c '
import json,sys,subprocess
jmp=sys.argv[1]
for e in json.load(sys.stdin):
    f=e.get("formatted",{}); k=f.get("key"); v=f.get("value")
    if k is None or not v: continue
    subprocess.run(["bpftool","map","update","pinned",jmp,
                    "key","%d"%k,"0","0","0","value","id","%d"%int(v)],
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
' "$JMP" 2>/dev/null || true
}
trap restore_jmp EXIT

step "รัน BPF_PROG_TEST_RUN repeat=$REPEAT ... (ไม่ส่ง packet ออกการ์ดจริง)"
# ยิงเข้า ratelimit prog ตรง ๆ (เป็น XDP prog ปกติ test_run ได้)
OUT=$(bpftool prog run pinned "$RL_PIN/prog" \
        data_in "$PKT" data_out "$OUTBIN" repeat "$REPEAT" 2>&1)
echo "$OUT"

# bpftool อาจพิมพ์ "Duration: N ns/run", "duration (average): Nns", หรือ "... N ns"
NSPR=$(echo "$OUT" | grep -oiE '([0-9]+)[[:space:]]*ns' | grep -oE '[0-9]+' | head -1)
RETV=$(echo "$OUT" | grep -oiE 'Return value: [0-9]+' | grep -oE '[0-9]+' | head -1)
case "${RETV:-}" in
    2) echo "    (Return=2 XDP_PASS — วัดเส้นทาง pass ถูกต้อง)";;
    1) warn "Return=1 XDP_DROP — ไม่ควรเกิดในเส้นทาง pass ตรวจ config/threshold";;
esac
LOG="$OUTDIR/micro_$(date +%Y%m%d_%H%M%S).txt"
{
    echo "repeat=$REPEAT"
    echo "ns_per_run=$NSPR"
    echo "git_note=วัดเส้นทาง pass ของ ratelimit ด้วย prog_test_run"
    echo "raw: $OUT"
} | tee "$LOG"
ok "ns/pkt (เส้นทาง pass) = ${NSPR:-?} ns  -> $LOG"
echo "เทียบโค้ดคนละแบบ: แก้ xdp_ratelimit.c -> ../../setup.sh reload 0 -> รัน micro_bench ซ้ำ"
