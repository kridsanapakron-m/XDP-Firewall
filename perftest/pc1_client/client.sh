#!/bin/bash
# ============================================================
#  client.sh (PC1 Ubuntu) — จำลอง "ผู้ใช้ปกติ" เพื่อวัดผลกระทบ
#  วัด HTTP latency (wrk), RTT (ping), goodput (iperf3)
#  รันพร้อมกับตอนที่ load.sh กำลังโจมตีอยู่ เพื่อดูว่าผู้ใช้ปกติเป็นไง
#
#  ใช้:
#    ./client.sh http  --dur 60             # wrk ไป http://PC2/ (เต็มที่)
#    ./client.sh http  --dur 60 --rate 2000 # จำกัด 2000 req/s (ให้อยู่ใต้ threshold)
#    ./client.sh ping  --dur 60
#    ./client.sh iperf --dur 30
#    ./client.sh all   --dur 60 [--rate N]
# ============================================================
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="$HERE/../common.conf"; source "$CONF"
OUT="$HERE/results_pc1"; mkdir -p "$OUT"
say(){ echo -e "[PC1-client] $*"; }

WHAT="${1:?ระบุ: http|ping|iperf|all}"; shift
DUR=60; RATE=""
while [ $# -gt 0 ]; do case "$1" in
    --dur)  DUR="$2"; shift 2;;
    --rate) RATE="$2"; shift 2;;   # req/s สำหรับ wrk (ว่าง = เต็มที่)
    *) shift;;
esac; done
TS=$(date +%Y%m%d_%H%M%S)

do_http(){
    local f="$OUT/${TS}_client_http.txt"
    local url="http://$PC2_SVC_IP:$HTTP_PORT/"
    # มี --rate → ใช้ curl probe (ยิงทีละ request เบา คุม rate ได้ ไม่ทะลุ threshold)
    #   (wrk มาตรฐานใน Ubuntu ไม่มี -R เลยคุม rate ไม่ได้ จึงใช้ curl แทนในโหมด legit)
    if [ -n "$RATE" ]; then
        command -v curl >/dev/null || { say "ไม่มี curl"; return; }
        local interval; interval=$(awk -v r="$RATE" 'BEGIN{printf "%.4f", 1/r}')
        say "วัด HTTP latency ${DUR}s ด้วย curl probe (~${RATE} req/s, sequential) -> $url"
        local tmp; tmp=$(mktemp)
        local end=$(( $(date +%s) + DUR )) ok=0 fail=0 t
        while [ "$(date +%s)" -lt "$end" ]; do
            if t=$(curl -o /dev/null -s -m 2 -w '%{time_total}' "$url" 2>/dev/null); then
                echo "$t" >> "$tmp"; ok=$((ok+1))
            else
                fail=$((fail+1))
            fi
            sleep "$interval"
        done
        {
            echo "http_url=$url duration_s=$DUR rate_req_s=$RATE"
            echo "requests_ok=$ok requests_failed=$fail"
            sort -n "$tmp" | awk '{a[NR]=$1*1000} END{
                if(NR==0){print "no_samples";exit}
                i50=int((NR-1)*0.50)+1; i90=int((NR-1)*0.90)+1; i99=int((NR-1)*0.99)+1
                printf "latency_ms_p50=%.2f\nlatency_ms_p90=%.2f\nlatency_ms_p99=%.2f\nlatency_ms_max=%.2f\n",a[i50],a[i90],a[i99],a[NR]
            }'
        } | tee "$f"
        rm -f "$tmp"
    else
        command -v wrk >/dev/null || { say "ไม่มี wrk (apt install wrk)"; return; }
        say "วัด HTTP latency ${DUR}s ด้วย wrk (เต็มที่) -> $url"
        wrk -t2 -c20 -d"${DUR}s" --latency "$url" 2>&1 | tee "$f"
    fi
    say "เก็บผล -> $f  (ดู latency_ms_p50/p99 และ requests_failed)"
}
do_ping(){
    local f="$OUT/${TS}_client_ping.txt"
    local cnt=$(( DUR * 100 ))     # ping ทุก 10ms
    say "วัด RTT ${DUR}s (ping ทุก 10ms) -> $PC2_SVC_IP"
    ping -i 0.01 -c "$cnt" -q "$PC2_SVC_IP" 2>&1 | tee "$f"
    say "เก็บผล -> $f  (ดู rtt min/avg/max/mdev และ % packet loss)"
}
do_iperf(){
    command -v iperf3 >/dev/null || { say "ไม่มี iperf3 (apt install iperf3)"; return; }
    local f="$OUT/${TS}_client_iperf.txt"
    say "วัด goodput ${DUR}s (iperf3 -> $PC2_SVC_IP:$IPERF_PORT)  [ต้องมี iperf3 -s บน PC2]"
    iperf3 -c "$PC2_SVC_IP" -p "$IPERF_PORT" -t "$DUR" 2>&1 | tee "$f"
    say "เก็บผล -> $f"
}

case "$WHAT" in
    http) do_http;;
    ping) do_ping;;
    iperf) do_iperf;;
    all)  do_ping & do_http; wait;;
    *) echo "ไม่รู้จัก: $WHAT"; exit 1;;
esac