#!/bin/bash
# ============================================================
#  00_prep.sh — เตรียม PC2 ให้พร้อมและคงที่ก่อนวัดผล
#  รันครั้งเดียวหลัง boot / ก่อนเริ่มชุดทดสอบ (ต้อง sudo)
# ============================================================
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"; load_conf

[ "$(id -u)" -eq 0 ] || { err "ต้องรันด้วย sudo"; exit 1; }

hr; step "ตรวจเครื่องมือที่ต้องใช้บน PC2"
need clang bpftool ethtool ip python3 || warn "มีบางตัวหาย — apt install ให้ครบก่อน (ดู README)"
need mpstat || warn "ไม่มี mpstat: apt install sysstat (จะวัด CPU ไม่ได้)"
command -v bpftop   >/dev/null && ok "มี bpftop (ดู ns/pkt แบบ real-time ได้)"
command -v xdp-bench >/dev/null && ok "มี xdp-bench (ไว้ทำ baseline)"

hr; step "ตรวจ driver ของการ์ด (native XDP รองรับไหม)"
for IF in "$PC2_IN_IF" "$PC2_OUT_IF"; do
    drv=$(ethtool -i "$IF" 2>/dev/null | awk '/^driver:/{print $2}')
    case "$drv" in
        igb|igc|ixgbe|i40e|ice|mlx5_core|bnxt_en) ok "$IF -> driver '$drv' (รองรับ native XDP)";;
        "") err "$IF: อ่าน driver ไม่ได้ (การ์ดชื่อถูกไหม?)";;
        *)  warn "$IF -> driver '$drv' อาจได้แค่ xdpgeneric (ช้ากว่า native มาก)";;
    esac
done

hr; step "ปรับ NIC + ระบบให้ผลนิ่ง"
systemctl stop irqbalance 2>/dev/null && ok "หยุด irqbalance แล้ว" || warn "ไม่มี/หยุด irqbalance ไม่ได้"
if command -v cpupower >/dev/null; then
    cpupower frequency-set -g performance >/dev/null 2>&1 && ok "ตั้ง CPU governor = performance" || warn "ตั้ง governor ไม่ได้"
else
    warn "ไม่มี cpupower (apt install linux-tools-common) — governor ไม่ถูกตั้ง"
fi
for IF in "$PC2_IN_IF" "$PC2_OUT_IF"; do
    ethtool -A "$IF" rx off tx off 2>/dev/null && ok "$IF: ปิด flow control" || warn "$IF: ปิด flow control ไม่ได้"
done
ethtool -K "$PC2_IN_IF" lro off 2>/dev/null && ok "$PC2_IN_IF: ปิด LRO (จำเป็นสำหรับ ixgbe + xdpdrv)"

echo
read -rp "จะล็อกให้ IN_IF ใช้ RX queue เดียวไหม? (ช่วยให้เห็นความต่างชัดที่ 1G) [y/N] " a
if [ "${a,,}" = "y" ]; then
    ethtool -L "$PC2_IN_IF" combined 1 2>/dev/null && ok "ตั้ง $PC2_IN_IF เป็น 1 queue" \
        || warn "ตั้ง 1 queue ไม่ได้ (การ์ดบางรุ่นไม่รองรับ)"
fi

hr; step "ตรวจ ARP/IP ของขา redirect"
ip -4 addr show dev "$PC2_OUT_IF" | grep -q "inet " \
    && warn "$PC2_OUT_IF มี IP อยู่ — แนะนำ flush เพื่อกัน ARP กวน: ip addr flush dev $PC2_OUT_IF" \
    || ok "$PC2_OUT_IF ไม่มี IP (ดีสำหรับ redirect)"
sysctl -qw net.ipv4.conf.all.arp_ignore=1
sysctl -qw net.ipv4.conf.all.arp_announce=2
ok "ตั้ง arp_ignore=1 arp_announce=2"

hr; step "สถานะ XDP ปัจจุบัน"
if xdp_loaded; then ok "ratelimit ถูกโหลดที่ $RL_PIN"; else warn "ยังไม่ได้โหลด XDP — รัน ../.. /setup.sh ก่อนเริ่มเคสจริง"; fi

hr; ok "เตรียม PC2 เสร็จ พร้อมทดสอบ"
echo "ขั้นต่อไป: ตั้งค่า ratelimit ด้วย  sudo ./rlconf.py set --threshold $RL_THRESHOLD --window-ms $RL_WINDOW_MS --block-s $RL_BLOCK_S --action drop"
