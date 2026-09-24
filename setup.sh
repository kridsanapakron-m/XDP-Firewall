#!/bin/bash
set -e

# ===== แก้ตรงนี้ตามเครื่องจริง =====
IN_IF=ens1f0     # NIC ฝั่งรับทราฟฟิกจาก attacker (Intel X550)
OUT_IF=ens1f1    # NIC ฝั่ง redirect ไป honeypot (Intel X550)
PIN=/sys/fs/bpf/ddos
# ===================================

clang -O2 -g -target bpf -c xdp_ratelimit.c -o xdp_ratelimit.o

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

# ล้างของเก่า (ลอง detach ทั้ง native และ generic เผื่อรันซ้ำ)
bpftool net detach xdpdrv     dev $IN_IF 2>/dev/null || true
bpftool net detach xdpgeneric dev $IN_IF 2>/dev/null || true
rm -rf $PIN
mkdir -p $PIN

# โหลด program + pin ทุก map ไว้ที่ $PIN
bpftool prog load xdp_ratelimit.o $PIN/prog type xdp pinmaps $PIN

ip link set dev $OUT_IF up
ip link set dev $IN_IF  up

# ----- เตรียม NIC ให้พร้อมสำหรับ native XDP -----
# X550 (ixgbe) ต้องปิด LRO ก่อน ไม่งั้น attach xdpdrv จะ fail
ethtool -K $IN_IF lro off 2>/dev/null || true

# (ทางเลือก) ปิด GRO ด้วยถ้าเจอปัญหา latency/ordering ตอนทดสอบ
# ethtool -K $IN_IF gro off

echo "[*] พยายาม attach แบบ native (xdpdrv) บน $IN_IF ..."
if bpftool net attach xdpdrv pinned $PIN/prog dev $IN_IF 2>/tmp/xdp_attach.err; then
    echo "[+] attach xdpdrv สำเร็จ (native mode, เร็วสุด)"
else
    echo "[!] xdpdrv ไม่ผ่าน: $(cat /tmp/xdp_attach.err)"
    echo "[*] fallback ไปใช้ xdpgeneric แทน"
    bpftool net attach xdpgeneric pinned $PIN/prog dev $IN_IF
fi

# tx_port[0] = ifindex ของ OUT_IF (little-endian)
IDX=$(cat /sys/class/net/$OUT_IF/ifindex)
bpftool map update pinned $PIN/tx_port key hex 00 00 00 00 \
    value hex $(printf '%02x %02x %02x %02x' $((IDX&255)) $((IDX>>8&255)) $((IDX>>16&255)) $((IDX>>24&255)))

echo "Loaded. maps:"; ls $PIN
bpftool net show