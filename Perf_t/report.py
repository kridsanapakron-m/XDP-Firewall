#!/usr/bin/env python3
"""สรุปผลของ run_tests.sh เป็นตาราง ค่าแต่ละแถวเฉลี่ยจากทุกรอบที่ซ้ำ (rep)

    python3 report.py results/20261010

ทุกรอบมีไฟล์ <id>.meta (ค่าที่ทดสอบ), .b0/.b1 (ตัวนับของ B ก่อน/หลัง), .c0/.c1 (ของ C),
.client (บรรทัดแรกคือคำสั่งที่ใช้ยิง ตามด้วยผลของ pktgen / hping3 / wrk / h2load / iperf)
ค่าที่รายงานคือผลต่างระหว่างหลังกับก่อน
"""
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

BACKENDS = (1, 2, 3)
UNFRAGMENTED = {"udp", "established", "new-flows", "no-fragments"}


def in_test(meta, number):
    """ข้อ "1" รวมข้อย่อย 1.1 1.2 1.3  ส่วน "1.1" คือข้อย่อยนั้นข้อเดียว"""
    test = meta.get("test", "")
    return test == number or test.startswith(number + ".")


def read_pairs(path):
    pairs = {}
    if path.exists():
        for line in path.read_text().splitlines():
            key, _, value = line.partition("=")
            if _:
                pairs[key.strip()] = value.strip()
    return pairs


def to_ms(value, unit):
    return float(value) * {"us": 0.001, "ms": 1.0, "s": 1000.0}[unit]


def parse_client(text):
    """อ่านผลของ pktgen (sent=), hping3, wrk, h2load และ iperf"""
    result = {}
    if match := re.search(r"^sent=(\d+)", text, re.M):
        result["sent"] = float(match.group(1))
    if match := re.search(r"^(\d+) packets tra\w*itted", text, re.M):          # hping3 (สะกด tramitted)
        result["sent"] = float(match.group(1))
    if match := re.search(r"Requests/sec:\s+([\d.]+)", text):                 # wrk
        result["req_s"] = float(match.group(1))
        errors = sum(int(n) for n in re.findall(r"(?:connect|read|write|timeout) (\d+)", text))
        if match := re.search(r"Non-2xx or 3xx responses: (\d+)", text):
            errors += int(match.group(1))
        result["errors"] = errors
    for percent, value, unit in re.findall(r"^\s+(50|90|99)%\s+([\d.]+)(us|ms|s)\s*$", text, re.M):
        result[f"p{percent}_ms"] = to_ms(value, unit)
    if match := re.search(r"finished in [\d.]+\w+, ([\d.]+) req/s", text):      # h2load
        result["req_s"] = float(match.group(1))
        if match := re.search(r"requests: .*?(\d+) failed, (\d+) errored, (\d+) timeout", text):
            result["errors"] = float(match.group(1))     # failed รวม errored และ non-2xx แล้ว
        header = re.search(r"^\s+(min\s+max.*)$", text, re.M)
        values = re.search(r"^time for request:\s+(.*)$", text, re.M)
        if header and values:
            fields = dict(zip(header.group(1).split(), values.group(1).split()))
            for name in ("mean", "p99"):
                if match := re.fullmatch(r"([\d.]+)(us|ms|s)", fields.get(name, "")):
                    result[f"{name}_ms" if name == "mean" else "p99_ms"] = to_ms(*match.groups())
    sums = re.findall(r"^\[SUM[^\]]*\].*?([\d.]+) ([KMG]?)bits/sec", text, re.M)   # iperf
    if sums:
        value, unit = sums[-1]
        result["mbps"] = float(value) * {"K": 0.001, "": 1e-6, "M": 1.0, "G": 1000.0}[unit]
    return result


def measure(directory, run_id):
    meta = read_pairs(directory / f"{run_id}.meta")
    b0, b1 = read_pairs(directory / f"{run_id}.b0"), read_pairs(directory / f"{run_id}.b1")
    c0, c1 = read_pairs(directory / f"{run_id}.c0"), read_pairs(directory / f"{run_id}.c1")
    d = lambda before, after, key: float(after.get(key, 0)) - float(before.get(key, 0))
    seconds = d(b0, b1, "time_ns") / 1e9 or 1
    clock = float(b1.get("clk_tck", 100))
    m = parse_client((directory / f"{run_id}.client").read_text(errors="replace"))

    busy = d(b0, b1, "cpu_busy")
    m["lb_cores"] = busy / clock / seconds
    if (rx := d(b0, b1, "nic_rx_packets")) > 0:
        m["ns_per_pkt"] = busy / clock * 1e9 / rx
    if (runs := d(b0, b1, "xdp_run_cnt")) > 0:
        m["xdp_ns"] = d(b0, b1, "xdp_run_time_ns") / runs
    for key in b1:
        if key.startswith("stat_"):
            m[key[5:]] = d(b0, b1, key)

    received = sum(d(c0, c1, f"b{i}_udp") for i in BACKENDS)
    packets = sum(d(c0, c1, f"b{i}_rx_packets") for i in BACKENDS) or 1
    if m.get("sent"):
        m["sent_kpps"] = m["sent"] / seconds / 1000
        # fragment ถูก backend ประกอบกลับก่อนนับ จึงคิด loss เฉพาะ UDP ที่ไม่แบ่ง
        if in_test(meta, "1.1") or in_test(meta, "2") or meta.get("traffic") in UNFRAGMENTED:
            m["loss_pct"] = max(0.0, (m["sent"] - received) / m["sent"] * 100)
    for i in BACKENDS:
        quota = float(c1.get(f"b{i}_quota_pct", 0)) or 100
        cpu = d(c0, c1, f"b{i}_cpu_usec") / (seconds * 1e6) * 100
        m[f"b{i}_cpu"] = cpu
        m[f"b{i}_util"] = cpu / quota
        m[f"b{i}_share"] = d(c0, c1, f"b{i}_rx_packets") / packets * 100
    utils = [m[f"b{i}_util"] for i in BACKENDS]
    if statistics.mean(utils) > 0:
        m["balance"] = max(utils) / statistics.mean(utils)
    return meta, m


def load(directory):
    groups = defaultdict(list)
    for meta_file in sorted(directory.glob("*.meta"), key=lambda path: path.stat().st_mtime_ns):  # ลำดับที่รัน
        meta, metrics = measure(directory, meta_file.stem)
        key = tuple((k, v) for k, v in meta.items() if k not in ("rep", "traffic_error"))
        groups[key].append(metrics)
    rows = []
    for key, runs in groups.items():
        names = {name for run in runs for name in run}
        average = {n: statistics.mean(r[n] for r in runs if n in r) for n in names}
        average["reps"] = len(runs)
        rows.append((dict(key), average))
    return rows


def throughput(m):
    """งานที่ทำได้: req/s ของ web หรือ Mbit/s ของ elephant"""
    return m.get("req_s", m.get("mbps"))


def workload_order(workload):
    """web-1k web-10k web-100k web-1m web-mix แล้วตามด้วย elephant"""
    order = ["web-1k", "web-10k", "web-100k", "web-1m", "web-mix", "elephant"]
    return order.index(workload) if workload in order else len(order)


def capacity(rows):
    """throughput รวมของ backend ทุกตัว ต่อ (scenario, workload) จากข้อ 0"""
    total = defaultdict(float)
    for meta, m in rows:
        if in_test(meta, "0") and throughput(m) is not None:
            total[meta["scenario"], meta.get("workload")] += throughput(m)
    for workload in {w for _, w in total}:
        if ("equal", workload) in total and ("dynamic_after", workload) in total:
            total["dynamic", workload] = (total["equal", workload] + 2 * total["dynamic_after", workload]) / 3
    return total


def table(title, rows, keys, columns):
    if not rows:
        return
    print(f"\n{title}")
    header = keys + [name for name, _ in columns]
    lines = [header]
    for meta, m in rows:
        line = [meta.get(k, "") for k in keys]
        for name, fmt in columns:
            value = m.get(name)
            line.append("-" if value is None else format(value, fmt))
        lines.append(line)
    widths = [max(len(str(line[i])) for line in lines) for i in range(len(header))]
    for line in lines:
        print("  " + "  ".join(str(cell).rjust(width) for cell, width in zip(line, widths)))


def main():
    directory = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    rows = load(directory)
    caps = capacity(rows)
    by_test = lambda number, **match: [(meta, m) for meta, m in rows if in_test(meta, number)
                                       and all(meta.get(k) == v for k, v in match.items())]
    backend = [(f"b{i}_{kind}", fmt) for kind, fmt in (("util", ".2f"),) for i in BACKENDS]
    print(f"ผลจาก {directory}  (ค่าเฉลี่ยของทุกรอบ, reps = จำนวนรอบ)")

    test0 = sorted(by_test("0"), key=lambda row: (row[0]["scenario"], workload_order(row[0].get("workload")),
                                                  row[0]["backend"]))
    table("ข้อ 0  capacity ของ backend (ยิงตรง)", test0, ["scenario", "workload", "backend"],
          [("req_s", ".0f"), ("mbps", ".0f"), ("mean_ms", ".2f"), ("b1_util", ".2f"),
           ("b2_util", ".2f"), ("b3_util", ".2f"), ("reps", "d")])
    for (scenario, workload), value in sorted(caps.items(), key=lambda item: (item[0][0], workload_order(item[0][1]))):
        unit = "Mbit/s" if workload == "elephant" else "req/s"
        print(f"  capacity รวม {scenario} {workload}: {value:.0f} {unit}")

    table("ข้อ 1.1  UDP (pktgen): CPU ของ B ต่อ packet", by_test("1.1"), ["mode", "size", "rate_pct"],
          [("sent_kpps", ".0f"), ("lb_cores", ".2f"), ("ns_per_pkt", ".0f"), ("loss_pct", ".2f"), ("reps", "d")])
    table("ข้อ 1.2  HTTP ไฟล์ 1 KB (wrk)", by_test("1.2"), ["mode", "conns"],
          [("req_s", ".0f"), ("p50_ms", ".2f"), ("p99_ms", ".2f"), ("lb_cores", ".2f"), ("errors", ".0f")])
    table("ข้อ 1.3  TCP stream (iperf)", by_test("1.3"), ["mode", "streams"],
          [("mbps", ".0f"), ("lb_cores", ".2f"), ("ns_per_pkt", ".0f")])
    table("ข้อ 2  จำนวน VIP (pktgen)  2.1 xdp  2.2 nft  2.3 ipt", by_test("2"), ["test", "mode", "vips", "pattern"],
          [("sent_kpps", ".0f"), ("lb_cores", ".2f"), ("ns_per_pkt", ".0f"), ("loss_pct", ".2f")])
    table("ข้อ 3  ต้นทุนทีละขั้น  3.0 ไม่มี LB ... 3.5 frag cache เต็ม", by_test("3"), ["test", "variant", "traffic"],
          [("xdp_ns", ".0f"), ("ns_per_pkt", ".0f"), ("lb_cores", ".2f"), ("loss_pct", ".2f"),
           ("req_s", ".0f"), ("p99_ms", ".2f"), ("conn_hit", ".0f"), ("conn_new", ".0f"),
           ("frag_hit", ".0f"), ("frag_miss", ".0f"), ("icmp_sent", ".0f"), ("xdp_pass", ".0f")])

    for test, keys in (("4", ["test", "scenario", "algo"]), ("5", ["test", "knob", "value"])):
        for workload in sorted({meta.get("workload") for meta, _ in by_test(test)}, key=workload_order):
            rows_of_test = by_test(test, workload=workload)
            for meta, m in rows_of_test:
                cap = caps.get((meta.get("scenario"), workload))
                if cap and throughput(m) is not None:
                    m["omega"] = throughput(m) / cap
            name = "อัลกอริทึม" if test == "4" else "ความไวของ AWFD (backend ไม่เท่ากัน)"
            tool = "iperf" if workload == "elephant" else "h2load"
            table(f"ข้อ {test}  {name}  workload={workload} ({tool})", rows_of_test, keys,
                  [("req_s", ".0f"), ("mbps", ".0f"), ("omega", ".3f"), ("mean_ms", ".2f")] + backend +
                  [("balance", ".2f"), ("awfd_dispatched", ".0f"), ("errors", ".0f")])
    print("\nomega = throughput ÷ capacity รวมจากข้อ 0 ของ workload เดียวกัน"
          "   balance = util สูงสุด ÷ util เฉลี่ย (1.00 = แบ่งตาม capacity พอดี)")


if __name__ == "__main__":
    main()
