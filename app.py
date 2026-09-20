#!/usr/bin/env python3
import json, struct, subprocess, socket, ipaddress, time, threading
from collections import deque
from datetime import datetime
from flask import Flask, jsonify, request, render_template

PIN         = "/sys/fs/bpf/ddos"
PROTO_MAP   = f"{PIN}/proto_config_map"
GLOBAL_MAP  = f"{PIN}/global_config_map"
RATE_MAP    = f"{PIN}/rate_limit_map"
TX_PORT     = f"{PIN}/tx_port"
IN_IF, OUT_IF = "ens33", "ens34"
PORT = 5000
UNBAN_ALLOWED_SOURCES = []           # เช่น ["192.168.184.201"]

PROTO_FMT  = "<QQII"                 # block_ns, window_ns, threshold, enabled  (24 B)
GLOBAL_FMT = "<6s6s"                 # honeypot_mac, firewall_mac                (12 B)
KEY_FMT    = "<II"                   # ip, proto                                  (8 B)
ENTRY_FMT  = "<QQI"                  # last_update, blocked_until, packet_count

# protocol ที่แสดงบนหน้าเว็บ  
PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1, "other": 0}
PROTO_NAME = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "OTHER", 2: "IGMP", 47: "GRE", 50: "ESP", 89: "OSPF"}

app = Flask(__name__)
unban_log = deque(maxlen=200)
log_lock  = threading.Lock()

def bt(*args):
    r = subprocess.run(["bpftool", "-j", *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())
    return r.stdout

hx     = lambda b: [f"{x:02x}" for x in b]
jbytes = lambda lst: bytes(int(x, 16) for x in lst)
u32key = lambda n: hx(struct.pack("<I", n))

def mac2b(s):
    p = s.strip().replace("-", ":").split(":")
    if len(p) != 6: raise ValueError(f"MAC ไม่ถูกต้อง: {s}")
    return bytes(int(x, 16) for x in p)

b2mac = lambda b: ":".join(f"{x:02x}" for x in b)
ktime_ns = lambda: time.clock_gettime_ns(time.CLOCK_MONOTONIC)

def iface_mac(name):
    with open(f"/sys/class/net/{name}/address") as f:
        return f.read().strip()

def flow_key(ip_str, proto):
    return struct.pack(KEY_FMT, int(ipaddress.IPv4Address(ip_str)), proto)

def add_log(ip, source, result):
    with log_lock:
        unban_log.appendleft({"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                              "ip": ip, "source": source, "result": result})

def read_proto(proto):
    j = json.loads(bt("map", "lookup", "pinned", PROTO_MAP, "key", "hex", *u32key(proto)))
    block_ns, win_ns, thr, en = struct.unpack(PROTO_FMT, jbytes(j["value"])[:24])
    return {"enabled": bool(en), "threshold": thr,
            "time_window_ms": win_ns / 1e6, "block_duration_s": block_ns / 1e9}

def write_proto(proto, c):
    val = struct.pack(PROTO_FMT,
                      int(float(c["block_duration_s"]) * 1e9),
                      int(float(c["time_window_ms"]) * 1e6),
                      int(c["threshold"]), 1 if c.get("enabled") else 0)
    bt("map", "update", "pinned", PROTO_MAP, "key", "hex", *u32key(proto), "value", "hex", *hx(val))

def read_global():
    j = json.loads(bt("map", "lookup", "pinned", GLOBAL_MAP, "key", "hex", *u32key(0)))
    hp, fw = struct.unpack(GLOBAL_FMT, jbytes(j["value"])[:12])
    return {"honeypot_mac": b2mac(hp), "firewall_mac": b2mac(fw)}

def write_global(g):
    val = struct.pack(GLOBAL_FMT, mac2b(g["honeypot_mac"]), mac2b(g["firewall_mac"]))
    bt("map", "update", "pinned", GLOBAL_MAP, "key", "hex", *u32key(0), "value", "hex", *hx(val))

def read_config():
    return {"global": read_global(),
            "protocols": {name: read_proto(num) for name, num in PROTOCOLS.items()}}

def write_config(c):
    write_global(c["global"])
    for name, num in PROTOCOLS.items():
        if name in c["protocols"]:
            write_proto(num, c["protocols"][name])

def dump_rate():
    now = ktime_ns(); rows = []
    for e in json.loads(bt("map", "dump", "pinned", RATE_MAP)):
        ip_int, proto = struct.unpack(KEY_FMT, jbytes(e["key"]))
        last, blocked_until, cnt = struct.unpack(ENTRY_FMT, jbytes(e["value"])[:20])
        rows.append({"ip": str(ipaddress.IPv4Address(ip_int)),
                     "proto": proto, "proto_name": PROTO_NAME.get(proto, str(proto)),
                     "packet_count": cnt,
                     "blocked": bool(blocked_until and now < blocked_until),
                     "blocked_remaining_s": max(0, (blocked_until - now) / 1e9) if blocked_until else 0,
                     "last_seen_s_ago": max(0, (now - last) / 1e9)})
    rows.sort(key=lambda r: (not r["blocked"], -r["packet_count"]))
    return rows

def delete_ip(ip_str, proto=None):
    """ลบ (ip, proto) ถ้า proto=None ลบทุก protocol ของ IP นั้น → คืนจำนวนที่ลบ"""
    ipaddress.IPv4Address(ip_str)
    protos = [proto] if proto is not None else \
             [r["proto"] for r in dump_rate() if r["ip"] == ip_str]
    n = 0
    for p in protos:
        try:
            bt("map", "delete", "pinned", RATE_MAP, "key", "hex", *hx(flow_key(ip_str, p))); n += 1
        except RuntimeError:
            pass
    return n

@app.route("/")
def index():
    return render_template("index.html", in_if=IN_IF, out_if=OUT_IF)

@app.get("/api/config")
def api_get_config():
    try: return jsonify(read_config())
    except Exception as e: return jsonify(error=str(e)), 500

@app.post("/api/config")
def api_set_config():
    try: write_config(request.json); return jsonify(ok=True, config=read_config())
    except Exception as e: return jsonify(error=str(e)), 400

@app.get("/api/interfaces")
def api_interfaces():
    try:
        return jsonify(in_if=IN_IF, out_if=OUT_IF, in_mac=iface_mac(IN_IF),
                       out_mac=iface_mac(OUT_IF), out_ifindex=socket.if_nametoindex(OUT_IF))
    except Exception as e: return jsonify(error=str(e)), 500

@app.post("/api/txport")
def api_txport():
    try:
        idx = socket.if_nametoindex(OUT_IF)
        bt("map", "update", "pinned", TX_PORT, "key", "hex", *u32key(0), "value", "hex", *u32key(idx))
        return jsonify(ok=True, ifindex=idx)
    except Exception as e: return jsonify(error=str(e)), 500

@app.get("/api/stats")
def api_stats():
    try: return jsonify(dump_rate())
    except Exception as e: return jsonify(error=str(e)), 500

@app.post("/api/unblock")
def api_unblock():
    try:
        d = request.json; n = delete_ip(d["ip"], d.get("proto"))
        add_log(f'{d["ip"]}/{PROTO_NAME.get(d.get("proto"), "ALL")}', f"web ({request.remote_addr})",
                "success" if n else "not found")
        return jsonify(ok=True, deleted=n)
    except Exception as e: return jsonify(error=str(e)), 400

@app.post("/api/clear")
def api_clear():
    try:
        for e in json.loads(bt("map", "dump", "pinned", RATE_MAP)):
            bt("map", "delete", "pinned", RATE_MAP, "key", "hex", *hx(jbytes(e["key"])))
        return jsonify(ok=True)
    except Exception as e: return jsonify(error=str(e)), 500

@app.get("/api/unban_log")
def api_unban_log():
    with log_lock: return jsonify(list(unban_log))

# ── สำหรับ honeypot 
@app.post("/unban")
def unban_ip():
    if UNBAN_ALLOWED_SOURCES and request.remote_addr not in UNBAN_ALLOWED_SOURCES:
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json(silent=True)
    if not data or "ip" not in data:
        return jsonify({"error": "Missing 'ip'"}), 400
    ip = data["ip"]; proto = data.get("proto")        # proto ไม่ส่งมา = ปลดทุก protocol
    try:
        n = delete_ip(ip, proto)
        add_log(ip, f"honeypot ({request.remote_addr})", "success" if n else "not found")
        print(f"[*] honeypot unban {ip}: deleted {n} entries")
        if n: return jsonify({"status": "success", "message": f"Unbanned ({n} entries)"}), 200
        return jsonify({"status": "ignored", "message": "Not found"}), 200
    except Exception as e:
        add_log(ip, f"honeypot ({request.remote_addr})", f"error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print(f"🚀 UI: http://0.0.0.0:{PORT}/   Unban API: POST /unban")
    app.run(host="192.168.184.169", port=PORT, debug=False, threaded=True)