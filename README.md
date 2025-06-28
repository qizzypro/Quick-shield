# Quick-shield
Quick-shield V0.1 — Complete for Linux
This system includes intelligent detection, aggressive mitigation, automatic IP banning, geo-blocking, service migration, and fallback protection — all designed to automatically detect and block Layer 4/7 DDoS and botnet attacks in real time.

# ⚙️ Detection & Monitoring
Feature	Description
Per-Port Connection Limits	Monitors connections per port (e.g., 22, 443, 8080) and bans IPs with excessive requests.
Flow-Based Pattern Detection	Detects botnets by counting how many flows (TCP connections) an IP makes.
TTL & Payload Heuristics	Analyzes network patterns like packet TTL or payload similarity (coming in V8).
Netstat/SS Parsing	Uses live system tools like ss and netstat to monitor real traffic.
GeoIP Lookup	Uses ipinfo.io API to identify the country of the attacking IP.

# 🔒 Mitigation & Blocking
Feature	Description
Auto IP Banning	Blocks IPs using iptables as soon as they're detected as abusive.
Auto Unban	Unbans IPs after a certain time period (default: 15 mins).
GeoIP Country Blocking	Blocks high-risk countries like RU, CN, IR, KP automatically.
Secondary Attacker Blocking	Blocks other IPs involved in the same attack (supporting nodes).
Fallback Blocking Mode	If detection fails, falls back to TCP SYN flood protection using rate-limiting.
Custom Ban Reasons Logged	Logs every IP with exact reason (e.g., "Too many connections on port 443").

# 🚦 Dynamic Defense Behavior
Feature	Description
Configurable Limits	Change protection behavior using a config file — no need to edit code.
Migration Trigger	If connection count crosses threshold (e.g., 500+), it triggers your custom mitigation script.
Live Daemon Mode	Runs 24/7, checking every few seconds (default: 3s interval).
Low Resource Usage	Works even on small VPS (low CPU/RAM use, no external databases).

# 📁 File & Logging System
Feature	Description
Ban Log File	Keeps all banned IPs in /var/log/banned_ips.txt
Main Log File	Writes all actions, errors, and defense alerts to /var/log/ddos_guard.log
PCAP Capture Limit Setting	(Planned) Allows limiting PCAP logging for future Layer 7 analysis.

# 🧠 Smart Config File (/etc/qizzypro.conf)

# 🧰 Summary of Protections by Layer
Layer	Protections
Layer 3 (Network)	IP banning, GeoIP blocking, rate-limiting
Layer 4 (Transport)	TCP SYN flood detection, port connection limits
Layer 7 (Application)	Flow-based heuristics (basic), pattern matching in progress


🚫 QizzyPro is a private, protected system. You are NOT allowed to copy, redistribute, or use it without permission.

© 2025 QizzyPro — All rights reserved.






