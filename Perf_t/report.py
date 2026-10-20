#!/usr/bin/env python3
"""สรุปผลของ run_tests.sh เป็นตาราง  ค่าแต่ละแถว = mean±CI95 (t-distribution) ของทุก rep ที่ใช้ได้

    python3 report.py results/20261012                      ตารางทุกข้อ + runs.csv + summary.csv ในโฟลเดอร์นั้น
    python3 report.py --capacity DIR SCENARIO WORKLOAD        พิมพ์ "C0 link_bound" จาก c0.tsv
    python3 report.py --c0-table DIR       สร้าง DIR/c0.tsv ใหม่ถ้ามีผลข้อ 0 ใหม่กว่า (run_tests.sh อ่าน C0 จากไฟล์นี้)
    python3 report.py --pilot DIR          สรุปท้าย pilot

ทุกรอบมีไฟล์ <id>.meta (ค่าที่ใช้จริง), .a0/.a1 .b0/.b1 .c0/.c1 (ตัวนับของ A B C ก่อน/หลังยิง),
.cpu-{a,b,c}.json.gz (mpstat ทุก 1 วินาทีช่วงยิง),
.client (คำสั่งและผลของเครื่องมือ), .ts (ข้อ 4.4 ตัวนับของ C ทุก 1 วินาที), .lat*.gz (log ของ h2load)
นิยามของ metric ตรงกับ 00_overview.txt หัวข้อ 5
"""
import csv
import gzip
import json
import math
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

BACKENDS = (1, 2, 3)
LINK_GOODPUT = 940.0            # Mbit/s ที่ TCP ได้จริงบน 1G
LINK_BOUND = 0.9                # C0 >= 90% ของ LINK_GOODPUT = ติด link แยกอัลกอริทึมไม่ได้
CV_FLAG = 0.10
CPU_KINDS = ("cores", "usr", "sys", "soft")    # b_<kind> จาก mpstat  หักรอบ idle แล้วเป็น lb_<kind>
STABLE_BALANCE, STABLE_SECONDS = 1.1, 3
T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262,
        10: 2.228, 12: 2.179, 15: 2.131, 20: 2.086, 30: 2.042}
C0_COLUMNS = ("scenario", "workload", "C0", "link_bound", "b1_thr", "b2_thr", "b3_thr")
LATENCY = {"p50_ms", "p99_ms", "p999_ms"}
SAT_NOTE = ("แถว sat = closed-loop ยิงเร็วสุดเท่าที่ระบบตอบทัน อ่านได้เฉพาะ throughput และ CPU  latency ไม่แสดง (\"-\") เพราะ"
            " latency ≈ connection ÷ throughput (Little's law) และ wrk2 วัดเทียบตารางเวลาที่ตามไม่ทัน")
NO_CV_FLAG = {"loss_lb", "loss_e2e", "error_rate", "conn_new_ratio", "frag_miss", "convergence_s"}
FORMATS = {"ns_per_fwd_pkt": ".0f", "ns_per_rx_pkt": ".0f", "xdp_ns": ".0f", "sent_pps": ".0f", "req_s": ".0f",
           "thr": ".0f", "mbps": ".0f", "cpu_us_per_req": ".1f", "avg_pkt_bytes": ".0f", "loss_lb": ".3f",
           "loss_e2e": ".3f", "error_rate": ".3f", "conn_new_ratio": ".3f", "icmp_ratio": ".3f",
           "frag_delivery_pct": ".1f", "frag_hit": ".0f", "frag_miss": ".0f", "frag_store_failed": ".0f",
           "conn_new": ".0f", "awfd_dispatched": ".0f", "omega": ".3f", "c_rx_drops": ".0f",
           "flood_dps": ".0f", "frag_dps": ".0f", "q_max_share": ".0f", "convergence_s": ".1f",
           "b1_thr": ".0f", "b2_thr": ".0f", "b3_thr": ".0f", "d_p50_ms": ".3f", "d_p99_ms": ".3f",
           "lookup_ns": ".0f", "d_lookup_ns": ".0f", "x": ".0f", "y": ".0f", "z": ".0f", "y_pct": ".1f",
           "z_pct": ".2f", "frag_share_pct": ".1f"}


def num(pairs, key):
    try:
        return float(pairs.get(key, 0) or 0)
    except ValueError:
        return 0.0


def read_pairs(path):
    pairs = {}
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip():
                pairs[key.strip()] = value.strip()
    return pairs


def in_test(meta, number):
    """ข้อ "1" รวมข้อย่อย 1.1 1.2 ...  ส่วน "1.1" คือข้อย่อยนั้นข้อเดียว"""
    test = meta.get("test", "")
    return test == number or test.startswith(number + ".")


# --- อ่านผลของเครื่องมือ ---

def binary(value, unit):
    return float(value) * 1024 ** "_KMGT".index(unit or "_")


def parse_traffic(text, m):
    """บรรทัด "traffic:" ที่ run_tests.sh พิมพ์หลัง pktgen / hping3 / tcpreplay"""
    for line in re.findall(r"^traffic: (.*)$", text, re.M):
        fields = dict(field.split("=", 1) for field in line.split() if "=" in field)
        count, rate = {"frag": ("frag_datagrams", "frag_dps"),
                       "flood": ("flood_datagrams", "flood_dps")}.get(fields.get("kind"), ("sent", "sent_pps"))
        m[count] = m.get(count, 0) + float(fields.get("sent", 0))
        m[rate] = m.get(rate, 0) + float(fields.get("achieved_pps", 0))
        m[count + "_target_pps"] = m.get(count + "_target_pps", 0) + float(fields.get("target_pps", 0))
        if "tuples" in fields:
            m["tuples"] = m.get("tuples", 0) + float(fields["tuples"])


def parse_http(text):
    """wrk2 หรือ h2load หนึ่งชุด: req/s, จำนวน request, error, goodput และ histogram ของ latency (ms)"""
    result, hist = {}, Counter()
    if match := re.search(r"Requests/sec:\s+([\d.]+)", text):                             # wrk2
        result["req_s"] = float(match.group(1))
        if match := re.search(r"(\d+) requests in", text):
            result["requests"] = float(match.group(1))
        errors = sum(int(n) for n in re.findall(r"(?:connect|read|write|timeout) (\d+)", text))
        if match := re.search(r"Non-2xx or 3xx responses: (\d+)", text):
            errors += int(match.group(1))
        result["errors"] = float(errors)
        if match := re.search(r"Transfer/sec:\s+([\d.]+)([KMGT]?)B", text):
            result["mbps"] = binary(*match.groups()) * 8 / 1e6
        spectrum = text.split("Detailed Percentile spectrum:", 1)[1].split("#[Mean", 1)[0] \
            if "Detailed Percentile spectrum:" in text else ""
        previous = 0
        for value, count in re.findall(r"^\s*([\d.]+)\s+[\d.]+\s+(\d+)\s+(?:[\d.]+|inf)\s*$", spectrum, re.M):
            hist[float(value)] += int(count) - previous
            previous = int(count)
    elif match := re.search(r"finished in [\d.]+\w+, ([\d.]+) req/s, ([\d.]+)([KMG]?)B/s", text):   # h2load
        result["req_s"] = float(match.group(1))
        result["mbps"] = binary(match.group(2), match.group(3)) * 8 / 1e6
        if match := re.search(r"requests: \d+ total, \d+ started, \d+ done, (\d+) succeeded, (\d+) failed", text):
            result["requests"], result["errors"] = float(match.group(1)), float(match.group(2))
    return result, hist


def read_latency_log(path):
    """log ของ h2load: เวลาเริ่ม (us) <tab> status (-1 = ล้มเหลว) <tab> เวลาจนจบ response (us)"""
    hist = Counter()
    with gzip.open(path, "rt") as log:
        for line in log:
            fields = line.split("\t")
            if len(fields) == 3 and fields[1] != "-1":
                hist[round(int(fields[2]) / 1000, 3)] += 1
    return hist


def quantile(hist, q):
    total, seen = sum(hist.values()), 0
    for value in sorted(hist):
        seen += hist[value]
        if seen >= q * total:
            return value
    return None


def parse_client(text, latency_logs):
    """ผลทั้งไฟล์ .client  ข้อ 0 และ 1.4 มีหลายชุด ("## backend i") รวมกัน และเก็บแยกเป็น b<i>_thr"""
    m, hist = {}, Counter()
    parse_traffic(text, m)
    parts = re.split(r"^## backend (\d+)$", text, flags=re.M)
    for backend, part in [("", parts[0])] + list(zip(parts[1::2], parts[2::2])):
        result, part_hist = parse_http(part)
        sums = re.findall(r"^\[SUM[^\]]*\].*?([\d.]+) ([KMG]?)bits/sec", part, re.M)          # iperf
        if sums and not result:
            result["mbps"] = float(sums[-1][0]) * {"K": 0.001, "": 1e-6, "M": 1.0, "G": 1000.0}[sums[-1][1]]
        for key, value in result.items():
            m[key] = m.get(key, 0) + value
        hist.update(part_hist)
        if backend and result:
            m[f"b{backend}_thr"] = result.get("req_s", result.get("mbps"))
    for path in latency_logs:
        hist.update(read_latency_log(path))
    if hist:
        for name, q in (("p50_ms", 0.50), ("p99_ms", 0.99), ("p999_ms", 0.999)):
            m[name] = quantile(hist, q)
    if "requests" in m:
        m["error_rate"] = m["errors"] / (m["requests"] + m["errors"]) * 100 if m["requests"] + m["errors"] else 0.0
    if "req_s" in m or "mbps" in m:
        m["thr"] = m.get("req_s", m.get("mbps"))
    return m


def convergence(meta, ts_path):
    """ข้อ 4.4: วินาทีจากเปลี่ยน quota จนถึงต้นช่วงที่ balance <= 1.1 ติดต่อกัน 3 วินาที  และสัดส่วนเวลาก่อนเปลี่ยน"""
    samples = [read_pairs_line(line) for line in ts_path.read_text().splitlines() if line.startswith("time_ns=")]
    change = num(meta, "quota_ns")
    if len(samples) < 2 or not change:
        return None, None
    streak = []
    for before, after in zip(samples, samples[1:]):
        seconds = (num(after, "time_ns") - num(before, "time_ns")) / 1e9
        utils = [(num(after, f"b{i}_cpu_usec") - num(before, f"b{i}_cpu_usec")) / 1e6 / seconds
                 / ((num(after, f"b{i}_quota_pct") or 100) / 100) for i in BACKENDS]
        if num(before, "time_ns") < change:
            continue
        balanced = statistics.mean(utils) > 0 and max(utils) / statistics.mean(utils) <= STABLE_BALANCE
        streak = streak + [num(before, "time_ns")] if balanced else []
        if len(streak) == STABLE_SECONDS:
            break
    start, end = num(samples[0], "time_ns"), num(samples[-1], "time_ns")
    before_share = min(1.0, max(0.0, (change - start) / (end - start))) if end > start else None
    return ((streak[0] - change) / 1e9 if len(streak) == STABLE_SECONDS else None), before_share


def read_pairs_line(line):
    return dict(field.split("=", 1) for field in line.split() if "=" in field)


def mpstat(path):
    """ค่าเฉลี่ยรายวินาทีของ mpstat (แถว cpu all) หน่วย core: cores = busy (100 − idle − iowait), usr (+nice),
    sys, soft (+irq)  และ seconds = จำนวนวินาทีที่เก็บได้  ไฟล์ไม่มีหรือไม่ครบ = {}"""
    try:
        host = json.loads(gzip.decompress(path.read_bytes()))["sysstat"]["hosts"][0]
    except (OSError, EOFError, ValueError, KeyError, IndexError):
        return {}
    loads = [next(c for c in sample["cpu-load"] if c["cpu"] == "all") for sample in host["statistics"]]
    if not loads:
        return {"seconds": 0}
    cores = lambda *keys: statistics.mean(sum(load[k] for k in keys) for load in loads) * host["number-of-cpus"] / 100
    return {"seconds": len(loads), "cores": host["number-of-cpus"] - cores("idle", "iowait"),
            "usr": cores("usr", "nice"), "sys": cores("sys"), "soft": cores("irq", "soft")}


# --- หนึ่งรอบ: ผลต่างของตัวนับหลังกับก่อนยิง ---

def measure(directory, run_id, meta, latency=True):
    snap = {name: read_pairs(directory / f"{run_id}.{name}") for name in ("a0", "a1", "b0", "b1", "c0", "c1")}
    d = lambda host, key: num(snap[host + "1"], key) - num(snap[host + "0"], key)
    window_c = d("c", "time_ns") / 1e9 or 1.0
    client = directory / f"{run_id}.client"
    m = parse_client(client.read_text(errors="replace") if client.exists() else "",
                     sorted(directory.glob(f"{run_id}.lat*.gz")) if latency else [])
    m["fire_s"] = (num(meta, "t_end_ns") - num(meta, "t_start_ns")) / 1e9 or d("b", "time_ns") / 1e9 or 1.0
    for host in "abc":
        for kind, value in mpstat(directory / f"{run_id}.cpu-{host}.json.gz").items():
            m[f"{host}_cpu_seconds" if kind == "seconds" else f"{host}_{kind}"] = value
    m["c_rx_drops"] = d("c", "nic_rx_dropped") + d("c", "nic_rx_missed_errors")
    m["b_rx_drops"] = d("b", "nic_rx_dropped") + d("b", "nic_rx_missed_errors")
    for key in snap["b1"]:
        if key.startswith("stat_"):
            m[key[5:]] = d("b", key)
    lb = meta.get("b_mode", "none") != "none"
    m["b_rx"] = d("b", "nic_rx_packets") + d("b", "nic_rx_missed_errors")
    m["b_fwd"] = m.get("xdp_redirect", 0) if meta.get("b_mode", "").startswith("xdp") else d("b", "nic_tx_packets")
    if (packets := d("b", "nic_rx_packets")) > 0:
        m["avg_pkt_bytes"] = d("b", "nic_rx_bytes") / packets
    if (runs := d("b", "xdp_run_cnt")) > 0:
        m["xdp_ns"] = d("b", "xdp_run_time_ns") / runs
    lookup = read_pairs(directory / f"{run_id}.lookup")
    if (calls := num(lookup, "lookup_calls")) > 0:
        m["lookup_ns"] = num(lookup, "lookup_ns") / calls
        if m["b_rx"] > 0:
            m["lookup_calls_per_pkt"] = calls / m["b_rx"]
    elif in_test(meta, "2") and "xdp_ns" in m:
        m["lookup_ns"] = m["xdp_ns"]                    # xdp: ทั้งโปรแกรม (bpf_stats)
    queues = {int(key[1:key.index("_")]): d("b", key) for key in snap["b1"] if re.fullmatch(r"q\d+_rx_packets", key)}
    if (total := sum(queues.values())) > 0:
        for queue, count in queues.items():
            m[f"q{queue}_share"] = count / total * 100
        m["q_max_share"] = max(queues.values()) / total * 100

    delivered = sum(d("c", f"b{i}_udp") for i in BACKENDS)
    if m.get("sent"):
        m["loss_e2e"] = max(0.0, (m["sent"] - delivered) / m["sent"] * 100)
        m["icmp_ratio"] = m.get("icmp_sent", 0) / m["sent"]
    if m.get("frag_datagrams"):
        m["frag_delivery_pct"] = sum(d("c", f"b{i}_udp_frag") for i in BACKENDS) / m["frag_datagrams"] * 100
    # packet ที่มาถึง B = มากกว่าระหว่างที่ NIC ของ B นับได้ กับที่ A ส่งจริง (fragment ละ 2 ชิ้น)
    # ixgbe ทิ้ง packet ตอนคิวเต็มโดยไม่นับใน rx_packets หรือ rx_missed_errors จึงต้องเทียบกับฝั่ง A ด้วย
    offered = m.get("sent", 0) + 2 * (m.get("frag_datagrams", 0) + m.get("flood_datagrams", 0))
    arrived = max(m["b_rx"], offered)
    if lb and offered > 0 and arrived > 0:
        m["loss_lb"] = max(0.0, (arrived - m["b_fwd"]) / arrived * 100)
    # 3.3 3.4 วัดความถูกต้อง: x = สั่งให้ส่ง (target × เวลา), y = ที่เครื่องมือรายงานว่าส่ง, z = ที่สำเร็จ
    seconds = num(meta, "duration") or m["fire_s"]
    if meta.get("test") == "3.3" and m.get("frag_datagrams"):
        m["x"], m["y"] = m["frag_datagrams_target_pps"] * seconds, m["frag_datagrams"]
        m["z"] = sum(d("c", f"b{i}_udp_frag") for i in BACKENDS)
        m["frag_share_pct"] = 2 * m["y"] / (2 * m["y"] + m.get("sent", 0)) * 100
    if meta.get("test") == "3.4" and m.get("sent"):
        m["x"], m["y"] = m["sent_target_pps"] * seconds, m["sent"]
        m["z"] = m.get("icmp_sent", 0) if meta.get("ip_size") == "1490" else delivered
    if m.get("x"):
        m["y_pct"], m["z_pct"] = m["y"] / m["x"] * 100, m["z"] / m["y"] * 100
    if meta.get("b_mode") == "xdp" and (flows := m.get("conn_hit", 0) + m.get("conn_new", 0)) > 0:
        m["conn_new_ratio"] = m["conn_new"] / flows

    packets = sum(d("c", f"b{i}_rx_packets") for i in BACKENDS)
    for i in BACKENDS:
        cpu = d("c", f"b{i}_cpu_usec") / (window_c * 1e6) * 100
        m[f"b{i}_cpu"], m[f"b{i}_util"] = cpu, cpu / (num(snap["c1"], f"b{i}_quota_pct") or 100)
        m[f"b{i}_throttled_pct"] = d("c", f"b{i}_throttled_usec") / (window_c * 1e6) * 100
        if packets > 0:
            m[f"b{i}_share"] = d("c", f"b{i}_rx_packets") / packets * 100
    requests = [d("c", f"b{i}_requests") for i in BACKENDS]
    if sum(requests) > 0:
        for i, count in zip(BACKENDS, requests):
            m[f"b{i}_req_pct"] = count / sum(requests) * 100
    utils = [m[f"b{i}_util"] for i in BACKENDS]
    if statistics.mean(utils) > 0:
        m["balance"] = max(utils) / statistics.mean(utils)
    if (ts := directory / f"{run_id}.ts").exists():
        m["convergence_s"], m["before_share"] = convergence(meta, ts)
        if m["convergence_s"] is None:
            del m["convergence_s"]
    return m


def lb_cost(meta, m, idle):
    """หัก CPU ตอนไม่มี traffic (ค่าเฉลี่ยของรอบ -idle ของข้อและ mode เดียวกัน) แล้วคูณเวลายิงจริง = CPU ที่ LB ใช้ทั้งรอบ"""
    if meta.get("b_mode", "none") == "none" or "b_cores" not in m:
        return
    for kind in CPU_KINDS:
        m[f"lb_{kind}"] = m[f"b_{kind}"] - idle.get(kind, 0.0)
    excess = m["lb_cores"] * m["fire_s"]
    if m["b_fwd"] > 0:
        m["ns_per_fwd_pkt"] = excess * 1e9 / m["b_fwd"]
    if m["b_rx"] > 0:
        m["ns_per_rx_pkt"] = excess * 1e9 / m["b_rx"]
    if m.get("requests"):
        m["cpu_us_per_req"] = excess * 1e6 / m["requests"]
    if meta.get("workload") == "elephant" and m.get("mbps"):
        m["cores_per_gbit"] = m["lb_cores"] / (m["mbps"] / 1000)


def exclusion(meta, m):
    if meta.get("traffic_error"):
        return "traffic_error"
    # 3.3 3.4 วัดความถูกต้องเป็นสัดส่วน: hping3 ยิงไม่ถึงเป้ารายงานเป็น y/x แทนการตัดรอบ
    #   และ hping3 ใช้ source port ใหม่ทุก datagram เกณฑ์ flow เดิม (EST) จึงใช้กับสองข้อนี้ไม่ได้
    correctness = meta.get("test") in ("3.3", "3.4")
    if meta.get("invalid") and not (correctness and meta["invalid"] == "rate"):
        return "invalid=" + meta["invalid"]
    ratio = m.get("conn_new_ratio")
    if ratio is not None and meta.get("profile") == "new" and ratio < 0.95:
        return f"profile new: conn_new_ratio {ratio:.3f} < 0.95"
    if ratio is not None and meta.get("profile") == "est" and ratio > 0.01 and not correctness:
        return f"profile est: conn_new_ratio {ratio:.3f} > 0.01"
    if meta.get("workload") and "thr" not in m:
        return "no_result"
    if in_test(meta, "2") and "lookup_ns" not in m:
        return "no_lookup: bpftrace/bpf_stats ไม่ได้ค่า"
    short = [host for host in "abc" if m.get(f"{host}_cpu_seconds", 0) < m["fire_s"] - 1]
    if short:
        return f"cpu_window: mpstat ของ {' '.join(short)} เก็บได้น้อยกว่าเวลายิง {m['fire_s']:.1f} s"
    return None


# --- รวมรอบเป็นแถว ---

def summarize(values):
    n = len(values)
    mean = statistics.mean(values)
    if n < 2:
        return {"mean": mean, "ci": None, "n": n, "cv": None}
    sd = statistics.stdev(values)
    t = T975[max(k for k in T975 if k <= n - 1)] if n - 1 <= 30 else 1.96
    return {"mean": mean, "ci": t * sd / math.sqrt(n), "n": n, "cv": sd / abs(mean) if mean else None}


def load(directory, prefix="", latency=True):
    """อ่านทุกรอบ  คืน (cases, runs)  case = แถวของตาราง (meta case=...) รวมทุก rep"""
    runs = []
    for meta_file in directory.glob("*.meta"):
        meta = read_pairs(meta_file)
        if meta.get("test", "").startswith(prefix) and "case" in meta:
            runs.append({"id": meta_file.stem, "meta": meta, "m": measure(directory, meta_file.stem, meta, latency)})
    idle, idle_any = defaultdict(list), defaultdict(list)
    for run in runs:
        meta, m = run["meta"], run["m"]
        if meta.get("kind") == "idle" and "b_cores" in m:
            idle[meta.get("test"), meta.get("mode") or meta.get("variant")].append(m)
            idle_any[meta.get("test")].append(m)
    for run in runs:
        meta = run["meta"]
        own = idle.get((meta.get("test"), meta.get("mode") or meta.get("variant"))) or idle_any.get(meta.get("test"))
        baseline = {kind: statistics.mean(m[f"b_{kind}"] for m in own) for kind in CPU_KINDS} if own else {}
        lb_cost(meta, run["m"], baseline if meta.get("kind") != "idle" else {})
        run["excluded"] = exclusion(meta, run["m"])
    cases = {}
    for run in sorted(runs, key=lambda r: int(num(r["meta"], "seq"))):
        if run["meta"].get("kind") == "idle":
            continue
        case = cases.setdefault(run["meta"]["case"], {"meta": run["meta"], "runs": [], "excluded": []})
        (case["excluded"] if run["excluded"] else case["runs"]).append(run)
    return cases, runs


def stats_of(case):
    """mean/CI/CV ของทุก metric  แถว sat ไม่มี latency (ดู SAT_NOTE)"""
    sat = case["meta"].get("level") == "sat"
    names = {k for run in case["runs"] for k, v in run["m"].items()
             if isinstance(v, (int, float)) and not (sat and k in LATENCY)}
    result = {name: summarize([run["m"][name] for run in case["runs"] if name in run["m"]]) for name in names}
    shares = sorted((int(name[1:-6]), s["mean"]) for name, s in result.items() if re.fullmatch(r"q\d+_share", name))
    case["q_share"] = "/".join(f"{share:.0f}" for _, share in shares)
    return result


def capacities(cases):
    """C0 ต่อ (scenario, workload) จากข้อ 0: throughput รวม, goodput (Mbit/s), throughput ของแต่ละ backend"""
    caps = {}
    for case in cases.values():
        meta, stats = case["meta"], case.get("stats", {})
        if in_test(meta, "0") and "thr" in stats:
            mbps = stats.get("mbps", {}).get("mean", 0.0)
            caps[meta["scenario"], meta["workload"]] = {
                "c0": stats["thr"]["mean"], "mbps": mbps, "link_bound": mbps >= LINK_BOUND * LINK_GOODPUT,
                "b": [stats.get(f"b{i}_thr", {}).get("mean", 0.0) for i in BACKENDS]}
    return caps


def c0_table(directory):
    """RUN_DIR/c0.tsv  สร้างใหม่เมื่อมีผลข้อ 0 ที่ใหม่กว่าไฟล์  อ่านแค่ throughput (ไม่อ่าน latency log)"""
    path = directory / "c0.tsv"
    stamp = path.stat().st_mtime_ns if path.exists() else -1
    if stamp < 0 or any(meta.stat().st_mtime_ns > stamp for meta in directory.glob("0.*.meta")):
        cases, _ = load(directory, prefix="0.", latency=False)
        for case in cases.values():
            case["stats"] = stats_of(case)
        lines = ["\t".join(C0_COLUMNS)]
        for (scenario, workload), cap in sorted(capacities(cases).items()):
            lines.append("\t".join([scenario, workload, f"{cap['c0']:.0f}", str(int(cap["link_bound"]))]
                                   + [f"{thr:.0f}" for thr in cap["b"]]))
        path.write_text("\n".join(lines) + "\n")
    caps = {}
    for line in path.read_text().splitlines()[1:]:
        scenario, workload, c0, bound, *backends = line.split("\t")
        caps[scenario, workload] = {"c0": float(c0), "link_bound": bound == "1", "b": [float(b) for b in backends]}
    return caps


def add_omega(cases, caps):
    """Ω = throughput ÷ C0 เฉพาะรอบ sat ของข้อ 4  ข้อ 4.4 ใช้ C0 ถ่วงตามเวลาก่อน/หลังเปลี่ยน quota"""
    for case in cases.values():
        meta = case["meta"]
        if not in_test(meta, "4") or meta.get("level") != "sat":
            continue
        cap = caps.get((meta.get("c0_scenario"), meta.get("workload")), {}).get("c0")
        before = caps.get(("balanced", meta.get("workload")), {}).get("c0")
        for run in case["runs"]:
            c0 = cap
            if meta.get("scenario") == "dynamic":
                share = run["m"].get("before_share") or 1 / 3
                c0 = share * before + (1 - share) * cap if cap and before else None
            if c0 and "thr" in run["m"]:
                run["m"]["omega"] = run["m"]["thr"] / c0


def cell(stats, name, case):
    if name == "q_share":
        return case.get("q_share") or "-"
    s = stats.get(name)
    if not s:
        return "-"
    fmt = FORMATS.get(name, ".2f")
    text = format(s["mean"], fmt) + ("" if s["ci"] is None else "±" + format(s["ci"], fmt))
    if s["cv"] is not None and s["cv"] > CV_FLAG and name not in NO_CV_FLAG:
        text += "!"
    return text


def table(title, cases, keys, columns, primary, note=""):
    if not cases:
        return
    print(f"\n{title}")
    lines = [keys + columns + ["n", f"cv%({primary})"]]
    for case in cases:
        stats = case["stats"]
        cv = stats.get(primary, {}).get("cv")
        lines.append([case["meta"].get(k, "") for k in keys] + [cell(stats, c, case) for c in columns]
                     + [str(len(case["runs"])), "-" if cv is None else f"{cv * 100:.1f}"])
    widths = [max(len(str(line[i])) for line in lines) for i in range(len(lines[0]))]
    for line in lines:
        print("  " + "  ".join(str(value).rjust(width) for value, width in zip(line, widths)))
    if note and any(case["meta"].get("level") == "sat" for case in cases):
        print("  " + note)


def write_csv(directory, cases, runs):
    meta_keys = sorted({k for run in runs for k in run["meta"]})
    metric_keys = sorted({k for run in runs for k, v in run["m"].items() if isinstance(v, (int, float))})
    with open(directory / "runs.csv", "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["id", "excluded"] + meta_keys + metric_keys)
        for run in sorted(runs, key=lambda r: int(num(r["meta"], "seq"))):
            writer.writerow([run["id"], run["excluded"] or ""] + [run["meta"].get(k, "") for k in meta_keys]
                            + [run["m"].get(k, "") for k in metric_keys])
    with open(directory / "summary.csv", "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(meta_keys + ["metric", "mean", "ci95", "n", "cv"])
        for case in cases.values():
            for name, s in sorted(case["stats"].items()):
                writer.writerow([case["meta"].get(k, "") for k in meta_keys]
                                + [name, s["mean"], "" if s["ci"] is None else s["ci"], s["n"],
                                   "" if s["cv"] is None else s["cv"]])


def loaded(directory, prefix="", latency=True):
    cases, runs = load(directory, prefix, latency)
    for case in cases.values():
        case["stats"] = stats_of(case)
    return cases, runs


def report(directory):
    cases, runs = loaded(directory)
    caps = capacities(cases)
    add_omega(cases, caps)
    for case in cases.values():
        case["stats"] = stats_of(case)
    by_test = lambda number, **match: [c for c in cases.values() if in_test(c["meta"], number)
                                       and all(c["meta"].get(k) == v for k, v in match.items())]
    gaps = [num(run["meta"], "gap_ms") / 1000 for run in runs if "gap_ms" in run["meta"]]
    print(f"ผลจาก {directory}   ค่า = mean±CI95 (t)   ! = CV > 10%   n = จำนวนรอบที่ใช้   CPU ของ B (mpstat) หักรอบ idle แล้ว")
    if gaps:
        print(f"เวลาเสียต่อรอบเฉลี่ย {statistics.mean(gaps):.1f} s (median {statistics.median(gaps):.1f} s, n = {len(gaps)})")

    table("ข้อ 0  C0: ยิงตรง backend 3 ตัวพร้อมกันแบบ sat", by_test("0"), ["scenario", "workload"],
          ["thr", "mbps", "b1_thr", "b2_thr", "b3_thr", "b1_util", "b2_util", "b3_util", "c_cores", "a_cores",
           "error_rate"], "thr", SAT_NOTE)
    for (scenario, workload), cap in sorted(caps.items()):
        unit = "Mbit/s" if workload == "elephant" else "req/s"
        flag = "  link-bound: แยกอัลกอริทึมไม่ได้" if cap["link_bound"] else ""
        print(f"  C0 {scenario} {workload}: {cap['c0']:.0f} {unit}  goodput {cap['mbps']:.0f} Mbit/s{flag}")

    test11 = by_test("1.1")
    table("ข้อ 1.1  UDP (pktgen): CPU ของ B ต่อ packet ที่ส่งต่อสำเร็จ", test11, ["mode", "size", "pps", "link_bound"],
          ["sent_pps", "lb_cores", "lb_usr", "lb_sys", "lb_soft", "ns_per_fwd_pkt", "loss_lb", "loss_e2e", "q_share",
           "a_cores", "c_cores", "c_rx_drops"], "ns_per_fwd_pkt")
    for mode in dict.fromkeys(c["meta"]["mode"] for c in test11):
        ok = [num(c["meta"], "pps") for c in test11 if c["meta"]["mode"] == mode and c["meta"]["size"] == "64"
              and c["meta"].get("link_bound") != "1" and c["stats"].get("loss_lb", {}).get("mean", 100) <= 0.1]
        print(f"  usable capacity {mode}: {max(ok):.0f} pps" if ok else f"  usable capacity {mode}: ต่ำกว่าระดับแรก")
    table("ข้อ 1.2  HTTP 1 KB: CPU ของ B ต่อ request", by_test("1.2"), ["mode", "workload", "level"],
          ["req_s", "cpu_us_per_req", "lb_cores", "lb_usr", "lb_sys", "lb_soft", "p50_ms", "p99_ms", "p999_ms",
           "error_rate", "a_cores"],
          "cpu_us_per_req", SAT_NOTE)
    table("ข้อ 1.3  TCP stream (iperf 16 stream)", by_test("1.3"), ["mode"],
          ["mbps", "lb_cores", "lb_usr", "lb_sys", "lb_soft", "cores_per_gbit", "avg_pkt_bytes", "q_share", "c_cores"],
          "cores_per_gbit")
    test14 = by_test("1.4")
    direct = next((c["stats"] for c in test14 if c["meta"]["mode"] == "direct"), {})
    for case in test14:
        for name in ("p50_ms", "p99_ms"):
            if name in case["stats"] and name in direct:
                case["stats"]["d_" + name] = {"mean": case["stats"][name]["mean"] - direct[name]["mean"],
                                              "ci": None, "n": 0, "cv": None}
    table("ข้อ 1.4  latency ที่ LB เพิ่ม (web-1k open-loop) d_ = ผ่าน VIP - ยิงตรง", test14, ["mode", "rate"],
          ["req_s", "p50_ms", "p99_ms", "p999_ms", "d_p50_ms", "d_p99_ms", "error_rate"], "p99_ms")
    test2 = by_test("2")
    for case in test2:
        base = next((c["stats"] for c in test2 if c["meta"]["vips"] == "1"
                     and c["meta"]["test"] == case["meta"]["test"] and c["meta"]["pattern"] == case["meta"]["pattern"]), {})
        if "lookup_ns" in case["stats"] and "lookup_ns" in base:
            case["stats"]["d_lookup_ns"] = {"mean": case["stats"]["lookup_ns"]["mean"] - base["lookup_ns"]["mean"],
                                            "ci": None, "n": 0, "cv": None}
    table("ข้อ 2  เวลาเลือก rule ต่อ packet (flow NEW)  xdp = ทั้งโปรแกรม (bpf_stats)  nft/ipt = ฟังก์ชันประเมิน rule"
          " (bpftrace)  d_ = เทียบ VIP 1", test2, ["test", "mode", "vips", "pattern", "pps"],
          ["sent_pps", "lookup_ns", "d_lookup_ns", "lookup_calls_per_pkt", "conn_new_ratio", "loss_lb"], "lookup_ns")
    table("ข้อ 3.0-3.2  ต้นทุนทีละขั้น (bpf_stats เปิด)", by_test("3.0") + by_test("3.1") + by_test("3.2"),
          ["test", "variant", "profile", "pps"],
          ["sent_pps", "xdp_ns", "ns_per_fwd_pkt", "lb_cores", "loss_lb", "loss_e2e", "conn_new_ratio"], "xdp_ns")
    test33 = by_test("3.3")
    reference = [c for c in by_test("3.2", profile="est") if test33 and c["meta"]["pps"] == test33[0]["meta"]["pps"]]
    reference = [dict(case, meta=dict(case["meta"], frag_pct="0 (3.2)")) for case in reference]
    table("ข้อ 3.3  fragment ปนกับ UDP ปกติ  x = datagram ที่สั่ง hping3, y = ที่ hping3 ส่งจริง, z = backend ประกอบได้"
          "  frag_share_pct = สัดส่วน fragment จริง", reference + test33, ["frag_pct", "pps"],
          ["x", "y", "y_pct", "z", "z_pct", "frag_share_pct", "frag_miss", "xdp_ns", "loss_lb"], "z_pct")
    table("ข้อ 3.4  PMTU (DF)  x = ที่สั่ง, y = ที่ส่งจริง, z = 1470 B: ถึง backend / 1490 B: ICMP frag-needed",
          by_test("3.4"), ["ip_size", "pps"], ["x", "y", "y_pct", "z", "z_pct", "icmp_ratio", "xdp_ns"], "z_pct")
    table("ข้อ 3.5  frag cache ถูกท่วม: flow ปกติระหว่าง flood source สุ่ม", by_test("3.5"),
          ["flood_rate", "frag_flow_rate", "b_frag_cache_map_max", "b_frag_timeout_s"],
          ["flood_dps", "frag_delivery_pct", "frag_hit", "frag_miss", "frag_store_failed", "lb_cores", "xdp_ns"],
          "frag_delivery_pct")

    latency = ["req_s", "p50_ms", "p99_ms", "p999_ms", "error_rate", "balance"]
    backend = ["b1_util", "b2_util", "b3_util", "b1_req_pct", "b2_req_pct", "b3_req_pct",
               "b1_throttled_pct", "b2_throttled_pct", "b3_throttled_pct", "conn_new", "awfd_dispatched"]
    for test in ("4.1", "4.2", "4.3", "4.4"):
        for workload in dict.fromkeys(c["meta"].get("workload") for c in by_test(test)):
            rows = by_test(test, workload=workload)
            flag = "  [link-bound]" if caps.get((rows[0]["meta"].get("c0_scenario"), workload), {}).get("link_bound") else ""
            table(f"ข้อ {test}  อัลกอริทึม  workload={workload}{flag}", rows, ["scenario", "mode", "algo", "level", "rate"],
                  latency[:1] + ["omega"] + latency[1:] + backend + (["convergence_s"] if test == "4.4" else []),
                  "p99_ms", SAT_NOTE)
            for case in rows:
                omega = case["stats"].get("omega")
                if omega and omega["mean"] < 0.9:
                    print(f"  ! {case['meta'].get('mode', 'xdp')} {case['meta']['algo']}: Ω = {omega['mean']:.3f} < 0.9  มี backend ที่แทบไม่ได้งาน")

    print("\nΩ = throughput ÷ C0 (เฉพาะ sat)   balance = util สูงสุด ÷ util เฉลี่ย   conn_new ควร >> 128 (connection เริ่มต้น)"
          "\nb<i>_req_pct = สัดส่วน request ที่ backend i ตอบ (nginx stub_status)"
          "   b<i>_throttled_pct = % ของเวลาที่ backend i ใช้ CPU เกิน quota จนถูกหยุด (cgroup)")

    excluded = [(run["id"], run["excluded"]) for run in runs if run["excluded"] and run["meta"].get("kind") != "idle"]
    if excluded:
        print(f"\nรอบที่ไม่เอามาเฉลี่ย ({len(excluded)} รอบ):")
        for run_id, reason in sorted(excluded):
            print(f"  {run_id}: {reason}")
    write_csv(directory, cases, runs)
    print(f"\nเขียน {directory / 'runs.csv'} และ {directory / 'summary.csv'}")


def pilot_summary(directory):
    """สรุปท้าย pilot: rate, เกณฑ์ flow profile, link-bound, ความยาวรอบ 40/60 s, เวลาเสียต่อรอบ"""
    cases, runs = loaded(directory)
    caps = capacities(cases)
    print("\n== สรุป pilot")
    invalid = sorted(run["id"] for run in runs if run["meta"].get("invalid"))
    print(f"  invalid=rate {len(invalid)} รอบ" + (f": {', '.join(invalid)}" if invalid else ""))
    for run in sorted(runs, key=lambda r: r["id"]):
        ratio, profile = run["m"].get("conn_new_ratio"), run["meta"].get("profile")
        if ratio is not None and profile in ("est", "new"):
            passed = ratio >= 0.95 if profile == "new" else ratio <= 0.01
            print(f"  conn_new_ratio {run['id']}: {ratio:.3f} ({profile}) {'ผ่าน' if passed else 'ไม่ผ่าน'}")
    print("  link-bound: " + (", ".join(f"{s}/{w}" for (s, w), cap in sorted(caps.items()) if cap["link_bound"]) or "ไม่มี"))
    lengths = {case["meta"].get("length"): case["stats"] for case in cases.values() if case["meta"].get("test") == "pilot"}
    if "40" in lengths and "60" in lengths:
        longer = False
        for name in ("p99_ms", "req_s"):
            short, long_ = lengths["40"].get(name), lengths["60"].get(name)
            if short and long_:
                margin = math.hypot(short["ci"] or 0, long_["ci"] or 0)
                differ = abs(short["mean"] - long_["mean"]) > margin
                longer |= differ
                print(f"  {name}: 40 s {cell(lengths['40'], name, {})}  60 s {cell(lengths['60'], name, {})}"
                      f"  {'ต่างเกิน CI95' if differ else 'ไม่ต่างเกิน CI95'}")
        print("  แนะนำ HTTP_DURATION=60" if longer else "  HTTP_DURATION=40 ใช้ได้")
    gaps = [num(run["meta"], "gap_ms") / 1000 for run in runs if "gap_ms" in run["meta"]]
    if gaps:
        print(f"  เวลาเสียต่อรอบ เฉลี่ย {statistics.mean(gaps):.1f} s (median {statistics.median(gaps):.1f} s, n = {len(gaps)})")


def capacity_cli(directory, scenario, workload):
    caps = c0_table(Path(directory))
    if (scenario, workload) not in caps:
        number = {"equal": "0.1", "unequal": "0.2"}.get(scenario, "0.3")
        sys.exit(f"ยังไม่มี C0 ของ scenario={scenario} workload={workload} ใน {directory}"
                 f"  รัน ./run_tests.sh {number} ก่อน (RUN_DIR เดียวกัน)")
    print(f"{caps[scenario, workload]['c0']:.0f} {int(caps[scenario, workload]['link_bound'])}")


def c0_table_cli(directory):
    c0_table(Path(directory))
    print(Path(directory) / "c0.tsv")


if __name__ == "__main__":
    commands = {"--capacity": (capacity_cli, 3), "--c0-table": (c0_table_cli, 1),
                "--pilot": (lambda directory: pilot_summary(Path(directory)), 1)}
    command, count = commands.get(sys.argv[1] if len(sys.argv) > 1 else "", (None, 0))
    if command and len(sys.argv) == count + 2:
        command(*sys.argv[2:])
    else:
        report(Path(sys.argv[1] if len(sys.argv) > 1 else "."))
