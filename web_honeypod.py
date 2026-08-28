from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

# IP ของเครื่อง Firewall ที่รัน API อยู่ (ต้องเป็นเส้นสำหรับ management)
FIREWALL_API_URL = "http://192.168.184.200:5000/unban"

# โค้ด HTML จำลองหน้าเว็บ (thank you gemini for gen this page)
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Check</title>
    <style>
        body { font-family: Arial; text-align: center; margin-top: 100px; background-color: #f4f4f9; }
        .box { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); display: inline-block; }
        button { background-color: #28a745; color: white; border: none; padding: 15px 30px; font-size: 16px; border-radius: 5px; cursor: pointer; }
        button:hover { background-color: #218838; }
    </style>
</head>
<body>
    <div class="box">
        <h2 style="color: #dc3545;">⚠️ ระบบตรวจพบทราฟฟิกผิดปกติ</h2>
        <p>หมายเลข IP ของคุณ ({{ client_ip }}) ส่งคำขอมากเกินไป</p>
        <p>กรุณายืนยันว่าคุณคือผู้ใช้งานปกติ ไม่ใช่บอทโจมตี (DDoS)</p>

        <form method="POST" action="/verify">
            <button type="submit">✅ ฉันเป็นคนจริงๆ (ปลดแบน IP)</button>
        </form>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    client_ip = request.remote_addr
    return render_template_string(HTML_PAGE, client_ip=client_ip)

@app.route('/verify', methods=['POST'])
def verify():
    client_ip = request.remote_addr

    try:
        # ยิงคำสั่ง API ไปหาเครื่อง Firewall เพื่อปลดแบน IP นี้
        response = requests.post(FIREWALL_API_URL, json={"ip": client_ip}, timeout=3)

        if response.status_code == 200:
            return f"<h3>✅ ปลดแบนสำเร็จ! กรุณารอ 3 วินาทีเพื่อกลับสู่หน้าเว็บปกติ...</h3><script>setTimeout(function(){{ window.location.href='http://192.168.184.150'; }}, 3000);</script>"
        else:
            return "<h3>❌ เกิดข้อผิดพลาดในการปลดแบน ติดต่อผู้ดูแลระบบ</h3>"

    except Exception as e:
        return f"<h3>❌ ไม่สามารถเชื่อมต่อกับ Firewall API ได้: {str(e)}</h3>"

if __name__ == '__main__':
    # รันเซิร์ฟเวอร์เว็บที่พอร์ต 80 (ต้องใช้สิทธิ์ sudo)
    print("🍯 Honeypot Web Server เริ่มทำงานที่พอร์ต 80...")
    app.run(host='0.0.0.0', port=80)