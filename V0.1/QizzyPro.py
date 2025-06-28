import subprocess
import time
import re
import requests
import configparser
from collections import defaultdict
from datetime import datetime

# === CONFIG ===
config = configparser.ConfigParser()
config.read('/etc/qizzypro.conf')  # You can move this path

# -- Advanced Mitigation Settings --
enable_fallback_blocking = config.getboolean("advanced_mitigation", "enable_fallback_blocking", fallback=True)
block_other_attack_contributors = config.getboolean("advanced_mitigation", "block_other_attack_contributors", fallback=False)
enable_pattern_detection = config.getboolean("advanced_mitigation", "enable_pattern_detection", fallback=True)
block_autodetected_patterns = config.getboolean("advanced_mitigation", "block_autodetected_patterns", fallback=True)
contributor_threshold = int(config.get("advanced_mitigation", "contributor_threshold", fallback="30"))
max_pcap_files = int(config.get("advanced_mitigation", "max_pcap_files", fallback="10"))

# -- DDoS Detection Settings --
DAEMON_FREQ = 3
PORT_CONNECTIONS = {22: (5, 600), 8080: (10, 600), 443: (10, 600)}
BAN_PERIOD = 900
GEO_BLOCK_COUNTRIES = ['RU', 'CN', 'IR', 'KP']
MIGRATION_THRESHOLD_CONN = 500
LOG_FILE = "/var/log/ddos_guard.log"
BANNED_IP_FILE = "/var/log/banned_ips.txt"
BANDWIDTH_DROP_RATE = "512kbit"
BANDWIDTH_DROP_PERIOD = 600

banned_ips = {}

# === UTILITIES ===
def log(message):
    msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}"
    print(msg)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

def ban_ip(ip, reason=""):
    if ip in banned_ips:
        return
    log(f"[BAN] {ip} → {reason}")
    subprocess.call(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    banned_ips[ip] = time.time()
    with open(BANNED_IP_FILE, "a") as f:
        f.write(ip + "\n")

def unban_expired_ips():
    current = time.time()
    for ip in list(banned_ips.keys()):
        if current - banned_ips[ip] > BAN_PERIOD:
            subprocess.call(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            banned_ips.pop(ip)
            log(f"[UNBAN] {ip}")

def get_country(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/country", timeout=2)
        if r.status_code == 200:
            return r.text.strip()
    except:
        pass
    return None

def geoip_blocker(ip):
    country = get_country(ip)
    if country in GEO_BLOCK_COUNTRIES:
        ban_ip(ip, f"GeoIP block ({country})")

# === DDoS Detection Functions ===

def detect_per_port():
    for port, (limit, _) in PORT_CONNECTIONS.items():
        output = subprocess.getoutput(f"ss -Hnt sport = :{port}")
        ip_hits = defaultdict(int)
        for line in output.splitlines():
            if len(line) < 5: continue
            ip = line.split()[4].split(":")[0]
            ip_hits[ip] += 1

        for ip, count in ip_hits.items():
            if count > limit:
                ban_ip(ip, f"{count} conns on port {port}")
                geoip_blocker(ip)
                if block_other_attack_contributors:
                    block_supporting_ips(port)

def block_supporting_ips(port):
    output = subprocess.getoutput(f"ss -Hnt sport = :{port}")
    for line in output.strip().splitlines():
        ip = line.split()[4].split(":")[0]
        ban_ip(ip, "Supporting attacker (secondary block)")

def pattern_heuristics():
    output = subprocess.getoutput("netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr")
    for line in output.splitlines():
        match = re.match(r"(\d+)\s+([\d\.]+)", line)
        if match:
            count = int(match.group(1))
            ip = match.group(2)
            if count > contributor_threshold:
                ban_ip(ip, f"Botnet pattern detected ({count} flows)")
                geoip_blocker(ip)

def fallback_blocking():
    if enable_fallback_blocking:
        log("[FALLBACK] Activating aggressive fallback defense")
        subprocess.call("iptables -I INPUT -p tcp --syn -m limit --limit 1/second --limit-burst 2 -j ACCEPT", shell=True)
        subprocess.call("iptables -A INPUT -p tcp --syn -j DROP", shell=True)

def migrate_services():
    all_lines = subprocess.getoutput("ss -Hnt").splitlines()
    conn_count = len(all_lines)
    if conn_count >= MIGRATION_THRESHOLD_CONN:
        log(f"[MIGRATION TRIGGERED] Connections = {conn_count}")
        subprocess.call("bash /root/migrate_services.sh", shell=True)

# === MAIN LOOP ===

def main_loop():
    log(" QizzyPro V0.1 Advanced Mitigation Started")
    if enable_fallback_blocking:
        fallback_blocking()

    while True:
        try:
            unban_expired_ips()
            detect_per_port()
            if enable_pattern_detection:
                pattern_heuristics()
            migrate_services()
        except Exception as e:
            log(f"[ERROR] {str(e)}")
        time.sleep(DAEMON_FREQ)

if __name__ == "__main__":
    main_loop()
