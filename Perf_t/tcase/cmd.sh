#!/bin/bash
# อ่านค่าด้วยคำสั่ง command line บนเครื่อง A, B หรือ C: แสดงคำสั่งและผลบนจอ แล้วคืนผลให้เก็บใส่ตัวแปรได้
#
# ใช้ในสคริปต์ (tcase/run_lib.sh source ไฟล์นี้ให้แล้ว):
#       cmd b 'ip -br addr'                                                แสดงคำสั่งและผล
#       rx0=$(cmd b 'cat /sys/class/net/$LB_IFACE/statistics/rx_packets')  เก็บผลไว้ในตัวแปร
#       s0=$(cmd b '$REPO/xdp_lb_ctl stats'); field xdp_redirect <<< "$s0"  ค่าที่อยู่ถัดจากคำว่า xdp_redirect
#       delta "B rx_packets" "$rx0" "$rx1"                                 ก่อน → หลัง และ Δ
#       ratio "ns ต่อครั้ง" "$t0" "$t1" "$n0" "$n1"                         (t1 − t0) ÷ (n1 − n0)
# ใช้จาก terminal บน A:  ./tcase/cmd.sh b 'bpftool prog show pinned $PIN/prog'
# ใส่คำสั่งใน '...' แล้วตัวแปรจะถูกแทนบนเครื่องปลายทาง: ก่อนรันจะ source perf_env.sh ของเครื่องนั้น
# ($LB_IFACE $VIP $REPO $PIN และ backend_ip ใช้ได้)  a = เครื่องนี้, b c = ssh ด้วย connection ค้างตัวเดียวกับ run_lib.sh
# shellcheck disable=SC2086   # ตั้งใจให้แยกคำ: ssh_options

CMD_DIR=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
# shellcheck source=../perf_env.sh
[ -n "${PERF_DIR:-}" ] || source "$CMD_DIR/../perf_env.sh"
ssh_options=${ssh_options:-"-o BatchMode=yes -o ConnectTimeout=5 -o ControlMaster=auto -o ControlPersist=10m \
-o ControlPath=/tmp/perf-ssh-%r@%h:%p"}

# remote <a|b|c> <คำสั่ง>: รันเงียบ ๆ ผลออก stdout  คำสั่งส่งทาง stdin ของ bash จึงไม่ต้อง escape เครื่องหมายคำพูด
remote() {
    case $1 in
        a) bash -s <<< ". $CMD_DIR/../perf_env.sh; $2" ;;
        b) ssh $ssh_options $SSH_LB bash -s <<< ". $PERF_DIR/perf_env.sh; $2" ;;
        c) ssh $ssh_options $SSH_SERVER bash -s <<< ". $PERF_DIR/perf_env.sh; $2" ;;
        *) echo "เครื่องต้องเป็น a b หรือ c" >&2; return 2 ;;
    esac
}

# cmd <a|b|c> <คำสั่ง>: แสดง "B$ คำสั่ง" และผล (เยื้อง) บนจอทาง stderr  คืนผลทาง stdout
#   คำสั่งล้มเหลวแสดง (exit N) แต่คืน 0 เพื่อไม่ให้การอ่านค่าหยุดการทดสอบที่ใช้ set -e  ค่าจริงอยู่ใน CMD_STATUS
cmd() {
    local output
    CMD_STATUS=0
    output=$(remote "$1" "$2") || CMD_STATUS=$?
    {
        echo "  ${1^^}\$ $2"
        if [ -n "$output" ]; then sed 's/^/     /' <<< "$output"; fi
        if [ $CMD_STATUS != 0 ]; then echo "     (exit $CMD_STATUS)"; fi
    } >&2
    if [ -n "$output" ]; then echo "$output"; fi
}

# field <ชื่อ>: ค่าที่อยู่ถัดจากคำว่า <ชื่อ> ตัวแรก (รับ "ชื่อ ค่า", "ชื่อ=ค่า", "ชื่อ: ค่า" และกลางบรรทัด)
field() { awk -v k="$1" '{ gsub(/[=:]/, " "); for (i = 1; i < NF; i++) if ($i == k) { print $(i + 1); exit } }'; }

# delta <ป้าย> <ก่อน> <หลัง>
delta() {
    awk -v l="$1" -v a="$2" -v b="$3" 'BEGIN {
        n = a ~ /^-?[0-9]+$/ && b ~ /^-?[0-9]+$/
        printf "  %-30s %16s → %-16s Δ %s\n", l, a == "" ? "-" : a, b == "" ? "-" : b, n ? sprintf("%.0f", b - a) : "-" }'
}

# ratio <ป้าย> <ตัวตั้งก่อน> <ตัวตั้งหลัง> <ตัวหารก่อน> <ตัวหารหลัง>
ratio() {
    awk -v l="$1" -v a0="$2" -v a1="$3" -v b0="$4" -v b1="$5" 'BEGIN {
        ok = a0 ~ /^[0-9]+$/ && a1 ~ /^[0-9]+$/ && b0 ~ /^[0-9]+$/ && b1 ~ /^[0-9]+$/ && b1 - b0 > 0
        printf "  %-30s %s\n", l, ok ? sprintf("%.1f", (a1 - a0) / (b1 - b0)) : "-" }'
}

if [ "$0" = "${BASH_SOURCE[0]}" ]; then
    if [ $# != 2 ]; then sed -n '2,13p' "$0"; exit 1; fi
    cmd "$1" "$2" >/dev/null
    exit $CMD_STATUS
fi
