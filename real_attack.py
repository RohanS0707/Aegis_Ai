# real_attack.py 



import requests
import time
import sys




AEGIS_API = "https://unallured-frederica-odontoid.ngrok-free.dev/api/simulate"

ATTACKS = {
    "1": ("Port Scan",    "192.168.1.200", 54321, 0),
    "2": ("DDoS",         "45.33.32.156",  54321, 80),
    "3": ("Brute Force",  "103.21.244.10", 54321, 22),
    "4": ("SQL Injection","198.199.88.50", 54321, 80),
    "5": ("XSS",          "91.108.56.142", 54321, 443),
}

def launch_attack(attack_type, src_ip, sport, dport):
    print(f"\n🚀 Launching {attack_type} from {src_ip}...")
    try:
        r = requests.post(AEGIS_API, json={
            "attack_type": attack_type,
            "src_ip": src_ip,
            "dst_ip": "192.168.1.1",
            "sport": sport,
            "dport": dport,
            "proto": "tcp"
        }, timeout=5)
        data = r.json()
        print(f"   ✅ Detected!  Confidence: {data.get('confidence', 'N/A')}%")
        print(f"   🚫 Blocked!   IP: {src_ip}")
        print(f"   📧 Email:     Sent to receiver")
        print(f"   📊 Dashboard: Check localhost:3000")
    except Exception as e:
        print(f"   ❌ Error: {e} — backeend may be down or ngrok expired. Check the dashboard for detections.")

print("="*55)
print("  ⚔  AEGIS AI — REAL ATTACK ")
print("  Legal use only — authorized network!")
print("="*55)
print()
print("  Decide Attack ")
print()
for k, (name, ip, sp, dp) in ATTACKS.items():
    print(f"  [{k}] {name:20} src: {ip}")
print("  [6] Launch ALL attacks")
print("  [0] Exit")
print()

choice = input("  Choice : ").strip()

if choice == "0":
    sys.exit(0)
elif choice == "6":
    print("\n🔥 Launching ALL attacks...")
    for k, (name, ip, sp, dp) in ATTACKS.items():
        launch_attack(name, ip, sp, dp)
        time.sleep(2)
elif choice in ATTACKS:
    name, ip, sp, dp = ATTACKS[choice]
    launch_attack(name, ip, sp, dp)
else:
    print("Invalid choice!")

print("\n✅ Done! ")