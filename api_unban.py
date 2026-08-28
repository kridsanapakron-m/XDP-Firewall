from flask import Flask, request, jsonify
import subprocess
import socket

app = Flask(__name__)

MAP_PATH = "/sys/fs/bpf/rate_limit_map" #เป็น staic path ต้องแก้เอง

def ip_to_hex_key(ip_str):
    # แปลง IP เป็น Bytes (Network Byte Order)
    packed_ip = socket.inet_aton(ip_str)

    #Reverse Bytes ของ IP เพื่อให้ตรงกับโครงสร้างใน Memory ของ XDP
    reversed_ip = packed_ip[::-1]

    hex_string = " ".join(f"{b:02x}" for b in reversed_ip)
    return hex_string

@app.route('/unban', methods=['POST'])
def unban_ip():
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({"error": "Missing 'ip'"}), 400

    target_ip = data['ip']

    try:
        hex_key = ip_to_hex_key(target_ip)
        print(f"[*] กำลังปลดแบน IP: {target_ip} (Hex: {hex_key})")

        # ใช้คำสั่ง bpftool เพื่อลบ IP ออกจาก Map
        # (สคริปต์นี้รันด้วย sudo อยู่แล้ว จึงไม่ต้องใส่ sudo หน้า bpftool)
        cmd = f"bpftool map delete pinned {MAP_PATH} key hex {hex_key}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            print(f"[+] ปลดแบนสำเร็จ!")
            return jsonify({"status": "success", "message": "Unbanned"}), 200
        else:
            print(f"[-] ไม่พบ IP ใน Map หรือลบไม่ได้")
            return jsonify({"status": "ignored", "message": "Not found"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # รันเซิร์ฟเวอร์ที่พอร์ต 5000 (0.0.0.0 คือรับจากทุก IP)
    print("🚀 Firewall API เริ่มทำงานที่พอร์ต 5000...")
    app.run(host='0.0.0.0', port=5000)