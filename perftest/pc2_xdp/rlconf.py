#!/usr/bin/env python3
# ============================================================
#  rlconf.py — ตั้งค่า/อ่าน ratelimit map ระหว่างทดสอบ
#  ใช้ฟังก์ชันจาก app.py ของโปรเจกต์ตรง ๆ (ไม่เขียน bpftool ซ้ำ)
#
#  ตัวอย่าง:
#    sudo ./rlconf.py set --proto tcp --threshold 1000 --window-ms 1000 --block-s 10 --action drop
#    sudo ./rlconf.py show
#    sudo ./rlconf.py clear          # ล้าง rate_limit_map (เริ่มรอบใหม่)
#    sudo ./rlconf.py blocked        # นับ entry ที่ถูกบล็อกอยู่
# ============================================================
import sys, os, argparse, json

# หา app.py จากรากโปรเจกต์ (perftest/pc2_xdp/ -> ../../)
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, PROJECT)

try:
    import app  # noqa: E402
except Exception as e:
    print(f"[x] import app.py ไม่ได้ ({e}). รัน script นี้บน PC2 ที่มีโปรเจกต์ครบ", file=sys.stderr)
    sys.exit(1)


def cmd_set(a):
    proto_num = app.PROTOCOLS.get(a.proto)
    if proto_num is None:
        print(f"[x] proto ต้องเป็นหนึ่งใน {list(app.PROTOCOLS)}", file=sys.stderr); sys.exit(1)
    cfg = {"enabled": True, "threshold": a.threshold,
           "time_window_ms": a.window_ms, "block_duration_s": a.block_s,
           "action": a.action}
    app.write_proto(proto_num, cfg)
    print(f"[+] ตั้ง {a.proto}: threshold={a.threshold} window={a.window_ms}ms "
          f"block={a.block_s}s action={a.action}")
    if a.honeypot_mac and a.firewall_mac:
        app.write_global({"honeypot_mac": a.honeypot_mac, "firewall_mac": a.firewall_mac})
        print(f"[+] ตั้ง global: honeypot={a.honeypot_mac} firewall={a.firewall_mac}")


def cmd_show(_):
    print(json.dumps(app.read_config(), indent=2, ensure_ascii=False))


def cmd_clear(_):
    try:
        import subprocess
        rows = json.loads(app.bt("map", "dump", "pinned", app.RATE_MAP))
        n = 0
        for e in rows:
            try:
                app.bt("map", "delete", "pinned", app.RATE_MAP,
                       "key", "hex", *app.hx(app.jbytes(e["key"]))); n += 1
            except Exception:
                pass
        print(f"[+] ล้าง rate_limit_map แล้ว ({n} entries)")
    except Exception as e:
        print(f"[x] clear ไม่สำเร็จ: {e}", file=sys.stderr); sys.exit(1)


def cmd_blocked(_):
    rows = app.dump_rate()
    blocked = [r for r in rows if r["blocked"]]
    print(f"total_flows={len(rows)} blocked={len(blocked)}")


def main():
    p = argparse.ArgumentParser(description="ตั้งค่า/อ่าน ratelimit map")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("set", help="เขียน config ของ proto ลง map")
    s.add_argument("--proto", default="tcp", choices=list(app.PROTOCOLS))
    s.add_argument("--threshold", type=int, required=True)
    s.add_argument("--window-ms", dest="window_ms", type=float, required=True)
    s.add_argument("--block-s", dest="block_s", type=float, required=True)
    s.add_argument("--action", default="drop", choices=["drop", "redirect"])
    s.add_argument("--honeypot-mac", default="")
    s.add_argument("--firewall-mac", default="")
    s.set_defaults(func=cmd_set)

    sub.add_parser("show", help="แสดง config ปัจจุบัน").set_defaults(func=cmd_show)
    sub.add_parser("clear", help="ล้าง rate_limit_map").set_defaults(func=cmd_clear)
    sub.add_parser("blocked", help="นับ flow ที่ถูกบล็อก").set_defaults(func=cmd_blocked)

    a = p.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
