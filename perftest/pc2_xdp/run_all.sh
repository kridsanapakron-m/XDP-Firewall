#!/bin/bash
# ============================================================
#  run_all.sh — ตัวคุมการทดสอบทั้งชุดบน PC2
#  ทำหน้าที่: สั่ง load (PC1) -> วัดผล (collect.sh) -> พัก -> ทำซ้ำ
#  รองรับ ORCH_MODE=ssh (สั่ง PC1/PC3 อัตโนมัติ) หรือ manual (บอกให้รันเอง)
#
#  ใช้:
#    sudo ./run_all.sh                 # รันทุกกลุ่มตามลำดับ
#    sudo ./run_all.sh throughput      # รันเฉพาะกลุ่มเดียว
#  กลุ่ม: baseline throughput redirect latency isolation accuracy scale compare
# ============================================================
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"; load_conf
[ "$(id -u)" -eq 0 ] || { err "ต้องรันด้วย sudo"; exit 1; }

LOAD_SLACK=5
BASELINE_DUR="${BASELINE_DUR:-30}"   # เวลาเก็บผลต่อรอบของ baseline (CPU% ไม่ขึ้นกับ dur ใช้ 30 พอ, ลดเวลา)
load_dur() { echo $(( WARMUP_S + $1 + LOAD_SLACK )); }

# ---------- จำกัดการประมวลผล XDP ไว้ที่ 1 core ----------
# การลด RX queue เหลือ 1 (ethtool -L combined 1) ทำใน setup_solo.sh "ก่อน" attach XDP แล้ว
#   (ถ้าทำตรงนี้หลัง XDP โหลด ethtool -L จะ reset NIC แล้วเตะ XDP หลุด → rl นับได้ 0)
# ตรงนี้ทำแค่ pin IRQ ของ queue เดียวไป CPU เดียว (ปลอดภัย ไม่ reset NIC)
pin_1core() {
    [ "${PIN_1CORE:-0}" = "1" ] || return 0
    local cid="${PIN_CORE_ID:-0}" mask irq n=0
    hr; step "จำกัด 1 core: pin IRQ ของ $PC2_IN_IF ไป CPU$cid"
    # ตรวจว่า queue ถูกลดเหลือ 1 แล้วหรือยัง (ต้องทำใน setup_solo.sh ก่อนโหลด XDP)
    local qn; qn=$(ethtool -l "$PC2_IN_IF" 2>/dev/null | awk '/^Current/{f=1} f&&/Combined/{print $2; exit}')
    [ -n "$qn" ] && [ "$qn" != 1 ] && warn "  $PC2_IN_IF ยังมี $qn queue (ไม่ใช่ 1) — รัน setup_solo.sh ใหม่ด้วย PIN_1CORE=1 ก่อน ไม่งั้น %CPU จะกระจายหลาย core"
    mask=$(printf '%x' $(( 1 << cid )))
    for irq in $(awk -v d="$PC2_IN_IF" '$0 ~ d {gsub(":","",$1); print $1}' /proc/interrupts); do
        if echo "$mask" > "/proc/irq/$irq/smp_affinity" 2>/dev/null; then n=$((n+1)); fi
    done
    step "  pin IRQ ของ $PC2_IN_IF ไป CPU$cid แล้ว $n ตัว (mask $mask)"
    systemctl stop irqbalance 2>/dev/null && step "  หยุด irqbalance (กันย้าย IRQ กลับ)" || true
    warn "  >> วัด cpu_busy เป็น 'core ที่ยุ่งสุด' (100% = CPU$cid เต็ม)"
}
restore_cores_hint() {
    [ "${PIN_1CORE:-0}" = "1" ] || return 0
    hr; warn "คืนค่า multi-queue หลังเทส:"
    echo "   sudo ethtool -L $PC2_IN_IF combined <จำนวนเดิม>   # เช่น 8"
    echo "   sudo systemctl start irqbalance"
}
# เรียกได้เฉพาะตอน XDP ถอดออกแล้ว (เช่นในกลุ่ม compare) — ethtool -L reset NIC จะเตะ XDP หลุดถ้ายัง attach อยู่
ensure_1queue() {
    [ "${PIN_1CORE:-0}" = "1" ] || return 0
    ethtool -L "$PC2_IN_IF" combined 1 2>/dev/null \
        && step "  1-core: ยืนยัน $PC2_IN_IF = 1 RX queue (วัด CPU ต่อ 1 core)" \
        || warn "  ลด queue ไม่สำเร็จ — CPU อาจเป็นเฉลี่ยหลาย core"
}

# ---------- สั่ง load ที่ PC1 ----------
# start_load <mode> <load-args...>   (background ใน ssh mode / prompt ใน manual)
start_load() {
    local args="$*"
    if [ "$ORCH_MODE" = "ssh" ]; then
        step "สั่ง PC1 ยิง load (ssh, background): $args"
        ssh -o StrictHostKeyChecking=no "$PC1_SSH" \
            "cd $REMOTE_PERFTEST_DIR/pc1_ubuntu && sudo ./load.sh $args" >/dev/null 2>&1 &
        LOAD_SSH_PID=$!
        sleep 1
    else
        echo; warn "ที่ PC1 (client+attacker) ให้รันคำสั่งนี้ แล้วรีบกลับมากด Enter:"
        echo "   Ubuntu : cd perftest/pc1_ubuntu && sudo ./load.sh $args"
        echo "   Windows: .\\load.ps1 $(echo "$args" | sed 's/--/-/g')   (ปรับ option ตามสคริปต์ Windows)"
        read -rp ">> กด Enter เมื่อ load เริ่มวิ่งแล้ว... " _
    fi
}
stop_load() {
    if [ "$ORCH_MODE" = "ssh" ] && [ -n "${LOAD_SSH_PID:-}" ]; then
        wait "$LOAD_SSH_PID" 2>/dev/null; LOAD_SSH_PID=""
    fi
}

# ---------- สั่ง client ปกติที่ PC1 (สำหรับกลุ่ม latency) ----------
start_client() {
    local args="$*"
    if [ "$ORCH_MODE" = "ssh" ]; then
        ssh -o StrictHostKeyChecking=no "$PC1_SSH" \
            "cd $REMOTE_PERFTEST_DIR/pc1_ubuntu && ./client.sh $args" > "$RESULTS_ROOT/last_client.txt" 2>&1 &
        CLIENT_PID=$!
    else
        warn "ที่ PC1 รัน client ปกติพร้อมกันด้วย:"
        echo "   Ubuntu : ./client.sh $args"
        echo "   Windows: .\\client.ps1 -What ${args%% *} -Dur $DURATION_S"
    fi
}

# ---------- ตั้งค่า ratelimit ก่อนเคส ----------
set_rl() {   # set_rl <action> <threshold>
    step "ตั้ง ratelimit: action=$1 threshold=${2:-$RL_THRESHOLD}"
    "$HERE/rlconf.py" set --proto udp --threshold "${2:-$RL_THRESHOLD}" \
        --window-ms "$RL_WINDOW_MS" --block-s "$RL_BLOCK_S" --action "$1" >/dev/null
    "$HERE/rlconf.py" set --proto tcp --threshold "${2:-$RL_THRESHOLD}" \
        --window-ms "$RL_WINDOW_MS" --block-s "$RL_BLOCK_S" --action "$1" >/dev/null
}
clear_rl() { "$HERE/rlconf.py" clear >/dev/null 2>&1 || true; }

# ---------- loop วัดซ้ำ ----------
# measure_reps <scenario> <variant> <dur> <load-args> [params...]
measure_reps() {
    local scn="$1" var="$2" dur="$3" load="$4"; shift 4; local params=("$@")
    local r
    for ((r=1; r<=REPEATS; r++)); do
        hr; step "[$scn/$var] รอบ $r/$REPEATS"
        clear_rl
        start_load $load --dur "$(load_dur "$dur")"
        "$HERE/collect.sh" "$scn" "$var" "$r" "$dur" "${params[@]}"
        stop_load
        step "พัก ${COOLDOWN_S}s (ให้ block หมดและ map เคลียร์)"; sleep "$COOLDOWN_S"
    done
}

prompt_dut() {   # ให้ operator สลับโปรแกรม XDP บน DUT
    hr; warn "ต้องสลับสถานะ XDP บน PC2 ก่อนกลุ่มนี้:"
    echo "   $1"
    read -rp ">> ทำเสร็จแล้วกด Enter... " _
}

# ================= กลุ่มการทดสอบ =================

g_baseline() {
    hr; step "=== กลุ่ม BASELINE (เพดาน + ต้นทุนการตรวจ ไว้เป็นตัวเทียบ) ==="
    prompt_dut "ถอด XDP ออกให้หมด:  sudo bpftool net detach xdpdrv dev $PC2_IN_IF ; (หรือ xdpgeneric)"
    ensure_1queue   # XDP ถอดแล้ว → ยืนยัน 1 RX queue (วัด no_xdp เป็น 1-core ให้เทียบ pass 1-core ได้)
    # (1) no_xdp ยิงตาม rate เดียวกับ throughput (64B) → เทียบ CPU กับ pass_64B_<rate>
    #     ผลต่าง (pass - no_xdp) ที่ rate เดียวกัน = "ต้นทุนการตรวจทุก packet" จริง ๆ
    local pps lbl
    for pps in $RATE_STEPS_PPS; do
        lbl=$(ppslabel "$pps")
        measure_reps baseline "no_xdp_64B_${lbl}pps" "$BASELINE_DUR" \
            "udp --pps $pps --size 64 --src single" pkt=64 target_pps=$pps path=no_xdp
    done
    # (2) no_xdp เต็ม line rate → เทียบ "ตัดเร็วประหยัดกว่า" กับ XDP drop (drop_64B_full)
    measure_reps baseline no_xdp_64B_full "$BASELINE_DUR" \
        "udp --pct 100 --size 64 --src single" pkt=64 rate_pct=100 path=no_xdp
    # (xdp-bench drop ตัดออกแล้ว — เคยทำ NIC ดับ และไม่จำเป็นต่อ no_xdp vs pass)
    prompt_dut "โหลด ratelimit กลับ:  cd ../standalone && sudo ./setup_solo.sh   (ให้ ratelimit กลับมาที่ $RL_PIN)"
}

# line rate (pps สูงสุด) ของขนาด packet หนึ่ง ๆ ที่ 1G (รวม 20B IFG+preamble)
linerate_pps() { awk -v s="$1" 'BEGIN{printf "%d", 1e9/((s+20)*8)}'; }
ppslabel() { awk -v p="$1" 'BEGIN{printf "%dk", p/1000}'; }  # 250000 -> 250k

g_throughput() {
    hr; step "=== กลุ่ม THROUGHPUT / CPU (ratelimit) ==="
    # threshold สูงมาก = เส้นทาง 'pass' ล้วน ไม่บล็อก
    # ต้องสูงกว่า offered pps สูงสุด × window มาก ๆ (1M pps × 1s = 1M → 1,000,000 ไม่พอ ชนพอดี)
    set_rl drop 2000000000
    local sz pps lr lbl
    for sz in $PKT_SIZES; do
        lr=$(linerate_pps "$sz")
        for pps in $RATE_STEPS_PPS; do
            if [ "$pps" -gt "$lr" ]; then
                warn "ข้าม ${sz}B @ $(ppslabel $pps)pps — เกิน line rate ของ ${sz}B ($(ppslabel $lr)pps) ยิงไม่ได้ที่ 1G"
                continue
            fi
            lbl=$(ppslabel "$pps")
            measure_reps throughput "pass_${sz}B_${lbl}pps" "$DURATION_S" \
                "udp --pps $pps --size $sz --src single" pkt=$sz target_pps=$pps path=pass
        done
    done
    step "ทดสอบเส้นทาง DROP (threshold ต่ำ ให้บล็อกทุก IP) — ยิงเต็ม line rate ของแต่ละขนาด"
    set_rl drop 100
    for sz in $PKT_SIZES; do
        measure_reps throughput "drop_${sz}B_full" "$DURATION_S" \
            "udp --pct 100 --size $sz --src single" pkt=$sz target_pps=linerate path=drop
    done
}

g_latency() {
    hr; step "=== กลุ่ม LATENCY ผู้ใช้ปกติ — เทียบ 3 แบบ ==="
    step "   (1) baseline ไม่มีโจมตี   (2) โจมตี+ไม่มี ratelimit   (3) โจมตี+มี ratelimit"
    local atk="udp --pps ${LAT_ATK_PPS:-800000} --size 64 --src single"   # attacker IP เดียว เกิน threshold
    local legit_rate="${LAT_LEGIT_RATE:-2000}" dur="$DURATION_S" thr="${LAT_THRESHOLD:-50000}" r

    lat_once() {   # lat_once <variant> <with_attack 0/1> <params...>
        local var="$1" atkon="$2"; shift 2
        for ((r=1; r<=REPEATS; r++)); do
            hr; step "[latency/$var] รอบ $r/$REPEATS"
            clear_rl
            start_client "all --dur $(load_dur "$dur") --rate $legit_rate"
            [ "$atkon" = 1 ] && start_load $atk --dur "$(load_dur "$dur")"
            "$HERE/collect.sh" latency "$var" "$r" "$dur" "$@"
            [ "$atkon" = 1 ] && stop_load
            [ "$ORCH_MODE" = ssh ] && wait "${CLIENT_PID:-$$}" 2>/dev/null || true
            step "พัก ${COOLDOWN_S}s"; sleep "$COOLDOWN_S"
        done
    }

    # ---- (1) baseline: ไม่มี attacker (ค่าอ้างอิงที่ดีที่สุด) ----
    # สำคัญ: ตั้ง threshold ให้เป็นค่าใช้งานจริงก่อน (ไม่งั้นค้างจากกลุ่ม throughput ที่ตั้ง 100 → legit โดนบล็อกเอง)
    set_rl drop "$thr"
    step "[1/3] baseline — ผู้ใช้ปกติ ไม่มี attacker (threshold ${thr}pps, legit ต้องไม่โดนบล็อก)"
    lat_once baseline_noattack 0 cond=baseline attacker=none

    # ---- (2) โจมตี + ไม่มี ratelimit (ถอด XDP ออก) ----
    prompt_dut "จำลอง 'ไม่มี ratelimit' — ถอด XDP ออกให้หมด:  sudo bpftool net detach xdpdrv dev $PC2_IN_IF"
    step "[2/3] โจมตี (attacker IP เดียว ${LAT_ATK_PPS:-800000}pps) + ไม่มี ratelimit ป้องกัน"
    lat_once no_ratelimit 1 cond=no_rl attacker=single_flood atk_pps="${LAT_ATK_PPS:-800000}"

    # ---- (3) โจมตี + มี ratelimit (บล็อก attacker) ----
    prompt_dut "โหลด ratelimit กลับ:  cd ../standalone && sudo ./setup_solo.sh"
    set_rl drop "$thr"
    step "[3/3] โจมตีเท่าเดิม + มี ratelimit (threshold ${thr}pps → บล็อก attacker)"
    lat_once with_ratelimit 1 cond=with_rl attacker=single_flood atk_pps="${LAT_ATK_PPS:-800000}" thr="$thr"

    hr; warn "ตีความ (ค่า latency/loss ของ legit อยู่ฝั่ง PC1: results_pc1/):"
    warn "  baseline  = ค่าอ้างอิงที่ดีที่สุด (ไม่มีโจมตี)"
    warn "  no_rl     = ควรแย่ลง (p99/loss พุ่ง) เพราะ flood ทะลุถึง host"
    warn "  with_rl   = ควรกลับมาใกล้ baseline (attacker โดนบล็อกที่ XDP) = ประโยชน์ของ ratelimit"
}

g_isolation() {
    hr; step "=== กลุ่ม ISOLATION (attacker เกิน limit + legit ปกติ พร้อมกัน) ==="
    # threshold สูง เพื่อให้ legit (wrk+ping ที่คุม rate แล้ว) อยู่ใต้ threshold ชัด ๆ
    # ส่วน attacker ตั้งให้เกิน threshold นี้ → โดนบล็อก (แต่ยังเบา ไม่ท่วม bandwidth)
    local iso_thr=50000          # threshold ต่อ IP (pps)
    local atk_pps=200000         # attacker เกิน threshold (แต่ < line rate)
    local legit_rate=2000        # legit wrk จำกัด req/s (~5-6k pps << 50000)
    step "พิสูจน์ว่า ratelimit บล็อกเฉพาะ attacker ($ATK_SRC_NET @ ${atk_pps}pps) แต่ legit ($PC1_IP, จำกัด ${legit_rate} req/s) ผ่านปกติ"
    "$HERE/rlconf.py" set --proto udp --threshold "$iso_thr" --window-ms "$RL_WINDOW_MS" --block-s "$RL_BLOCK_S" --action drop >/dev/null
    "$HERE/rlconf.py" set --proto tcp --threshold "$iso_thr" --window-ms "$RL_WINDOW_MS" --block-s "$RL_BLOCK_S" --action drop >/dev/null
    local r
    for ((r=1; r<=REPEATS; r++)); do
        hr; step "[isolation/attacker_vs_legit] รอบ $r/$REPEATS  (threshold ${iso_thr}pps/IP)"
        clear_rl
        # legit ปกติ (PC1_IP: wrk จำกัด rate + ping) + attacker (IP เดียว เกิน threshold) ยิงพร้อมกัน
        start_client "all --dur $(load_dur "$DURATION_S") --rate $legit_rate"
        start_load udp --pps "$atk_pps" --size 64 --src portrand --dur "$(load_dur "$DURATION_S")"
        "$HERE/collect.sh" isolation attacker_vs_legit "$r" "$DURATION_S" \
            attacker_ip="$ATK_SRC_NET" legit_ip="$PC1_IP" thr="$iso_thr" atk_pps="$atk_pps"
        stop_load
        [ "$ORCH_MODE" = ssh ] && wait "${CLIENT_PID:-$$}" 2>/dev/null || true
        step "พัก ${COOLDOWN_S}s"; sleep "$COOLDOWN_S"
    done
    hr
    warn "ตีความผล:"
    warn "  blocked_max ควร = 1 (เฉพาะ attacker $ATK_SRC_NET) — ถ้า >1 แปลว่า legit โดนบล็อกด้วย (threshold ต่ำไป)"
    warn "  p50/p99 + loss ของ legit (ฝั่ง PC1 results_pc1/) ควรใกล้เคียงตอนไม่มี attack = isolation สำเร็จ"
    warn "  HTTP ไม่ควรมี Socket errors/timeout แล้ว (legit ใต้ threshold)"
}

g_accuracy() {
    hr; step "=== กลุ่ม ACCURACY (ความแม่นยำการบล็อก) ==="
    step "ตั้ง threshold=$RL_THRESHOLD/${RL_WINDOW_MS}ms block=${RL_BLOCK_S}s แล้วยิง 1 IP เกิน threshold"
    set_rl drop "$RL_THRESHOLD"
    measure_reps accuracy single_ip_overlimit "$DURATION_S" \
        "udp --pps $((RL_THRESHOLD*5)) --size 64 --src single" src=single
    step "ยิง IP เดียวแต่หลาย source port (ทดสอบ race ข้าม core จาก RSS)"
    measure_reps accuracy single_ip_multiport "$DURATION_S" \
        "udp --pps $((RL_THRESHOLD*5)) --size 64 --src portrand" note=same_srcIP_rnd_port
}

g_scale() {
    hr; step "=== กลุ่ม SCALE / spoofed source ==="
    set_rl drop "$RL_THRESHOLD"
    local n
    for n in 1000 10000 60000 200000; do
        # ส่งจำนวน source IP ผ่าน --nsrc ตรง ๆ (load.sh สุ่มข้าม octet ให้ได้ครบจริง)
        measure_reps scale "src_${n}" "$DURATION_S" \
            "udp --pct 90 --size 64 --src random --nsrc $n" src_ips=$n
    done
    warn "เคส src=200000 (>65536) คาดว่า LRU map เริ่มไล่ entry ทิ้ง -> ดู blocked_max ว่าตันที่ ~65536 หรือหลุดเพิ่ม"
}

g_redirect() {
    hr; step "=== กลุ่ม REDIRECT (วัดเส้นทาง redirect ไป honeypot) ==="
    # FIREWALL_MAC ว่าง = อ่านจาก OUT_IF ให้เอง
    local fwmac="${FIREWALL_MAC:-$(cat /sys/class/net/$PC2_OUT_IF/address 2>/dev/null)}"
    if [ -z "${HONEYPOT_MAC:-}" ] || [ -z "$fwmac" ]; then
        err "กลุ่ม redirect ต้องตั้ง HONEYPOT_MAC (MAC ของ PC3) ใน common.conf ก่อน และ OUT_IF ต้องมีอยู่จริง — ข้ามกลุ่มนี้"
        return 0
    fi
    step "ตั้ง action=redirect  honeypot=$HONEYPOT_MAC  firewall=$fwmac  (threshold ต่ำ ให้ redirect ทุก IP)"
    local p
    for p in udp tcp; do
        "$HERE/rlconf.py" set --proto "$p" --threshold 100 \
            --window-ms "$RL_WINDOW_MS" --block-s "$RL_BLOCK_S" --action redirect \
            --honeypot-mac "$HONEYPOT_MAC" --firewall-mac "$fwmac" >/dev/null
    done
    warn "เช็คก่อน: OUT_IF ($PC2_OUT_IF) up+carrier ไป PC3, HONEYPOT_MAC = MAC จริงของการ์ด PC3"
    warn "  (ไม่ต้องใส่ $PC2_SVC_IP บน lo ของ PC3 — collect.sh นับที่ตัวนับการ์ด /proc/net/dev ก่อน IP stack เช็ก dst)"
    [ "$ORCH_MODE" = manual ] && read -rp ">> พร้อมแล้วกด Enter... " _
    local sz pc3dur=$(( REPEATS * (WARMUP_S + DURATION_S + COOLDOWN_S) ))
    for sz in $PKT_SIZES; do
        # ให้ PC3 นับ packet ที่ redirect มาถึง ตลอดช่วงของ packet size นี้
        if [ "$ORCH_MODE" = ssh ]; then
            ssh -o StrictHostKeyChecking=no "$PC3_SSH" \
                "cd $REMOTE_PERFTEST_DIR/pc3_honeypot && ./collect.sh redirect_${sz}B $pc3dur" \
                >/dev/null 2>&1 &
        else
            warn "ที่ PC3 รันคู่กัน:  ./collect.sh redirect_${sz}B $pc3dur"
        fi
        measure_reps redirect "redirect_${sz}B_100pct" "$DURATION_S" \
            "udp --pct 100 --size $sz --src single" pkt=$sz rate_pct=100 path=redirect
    done
    warn "เทียบ xdp_redirect (summary.csv) กับ rx_pps ที่ PC3 (pc3_honeypot/results_pc3/) ว่าใกล้กันไหม"
}

g_compare() {
    hr; step "=== กลุ่ม COMPARE: เทียบ iptables/nftables (นโยบายเดียวกัน) ==="
    prompt_dut "ถอด XDP แล้วใส่ nftables (ใส่ sudo ทุกบรรทัด! ถ้าใช้ ; sudo จะมีผลแค่บรรทัดแรก):
   sudo bpftool net detach xdpdrv dev $PC2_IN_IF
   sudo nft add table netdev ddos
   sudo nft add chain netdev ddos in '{ type filter hook ingress device $PC2_IN_IF priority -500; }'
   sudo nft add rule netdev ddos in ip protocol udp limit rate over ${RL_THRESHOLD}/second drop
   (ต้องเป็น family netdev เท่านั้น — hook ingress ไม่รองรับใน family ip)"
    ensure_1queue   # XDP ถอดแล้ว → ลด queue เหลือ 1 ได้ปลอดภัย (วัด CPU ต่อ 1 core เหมือน XDP)
    measure_reps compare nft_limit 30 "udp --pct 90 --size 64 --src single" tool=nftables
    prompt_dut "ลบ nftables แล้วใส่ iptables hashlimit แทน:
   sudo nft delete table netdev ddos
   sudo iptables -t raw -A PREROUTING -p udp -m hashlimit --hashlimit-above ${RL_THRESHOLD}/sec --hashlimit-mode srcip --hashlimit-name ddos -j DROP"
    measure_reps compare iptables_hashlimit 30 "udp --pct 90 --size 64 --src single" tool=iptables
    prompt_dut "ลบ rule แล้วโหลด XDP กลับ:
   sudo iptables -t raw -F PREROUTING
   cd ../standalone && sudo ./setup_solo.sh"
}

# ================= main =================
GRP="${1:-all}"
echo; step "เริ่มชุดทดสอบ  ORCH_MODE=$ORCH_MODE  REPEATS=$REPEATS  DURATION=${DURATION_S}s"
step "ผลรวมทั้งหมดจะอยู่ใน: $RESULTS_ROOT/summary.csv"
xdp_loaded || warn "ยังไม่ได้โหลด XDP — บางกลุ่มจะใช้ไม่ได้จนกว่าจะรัน setup.sh"
pin_1core

START=$(date +%s)
case "$GRP" in
    all) g_baseline; g_throughput; g_redirect; g_latency; g_isolation; g_accuracy; g_scale; g_compare;;
    baseline) g_baseline;; throughput) g_throughput;; redirect) g_redirect;;
    latency) g_latency;; isolation) g_isolation;; accuracy) g_accuracy;;
    scale) g_scale;; compare) g_compare;;
    *) err "ไม่รู้จักกลุ่ม: $GRP"; exit 1;;
esac
END=$(date +%s)

restore_cores_hint
hr; ok "เสร็จทั้งหมด ใช้เวลาจริง $(( (END-START)/60 )) นาที $(( (END-START)%60 )) วินาที"
ok "สรุปผล: $RESULTS_ROOT/summary.csv"
echo "ทำกราฟ/สรุปต่อด้วย:  python3 $HERE/../tools/summarize.py $RESULTS_ROOT/summary.csv"
