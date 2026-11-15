# Advanced Network Traffic Analysis Report

**Date:** 15-11-2026  
**Analyst:** Krishan Kumar  
**Task:** Week 5 - Task 4 (Advanced Network Traffic Analysis)  
**Capture Source:** `enterprise_traffic_capture.pcap`  

---

## 1. Executive Summary
A deep packet inspection (DPI) was conducted on a captured network traffic file (`enterprise_traffic_capture.pcap`) using **Wireshark** and **tcpdump** to identify potential security breaches and anomalous behavior. The investigation uncovered **three critical suspicious activities**: an internal TCP SYN port scan, periodic HTTP Command-and-Control (C2) beaconing, and DNS tunneling/exfiltration queries. Immediate network segmentation, firewall blocking, and DNS filtering are recommended.

---

## 2. Analysis Methodology
1. **Protocol Hierarchy & Conversations:** Reviewed Wireshark *Statistics > Protocol Hierarchy* and *Conversations* to identify top talkers and unusual port usage.
2. **Traffic Filtering:** Applied targeted Wireshark display filters and `tcpdump` expressions to isolate suspicious handshakes, cleartext HTTP payloads, and high-entropy DNS requests.
3. **Packet Stream Reconstruction:** Used *Follow TCP/HTTP Stream* to inspect payload contents and verify malicious intent.

---

## 3. Detailed Findings & Suspicious Network Activities

### Finding 1: Internal Network Reconnaissance (TCP SYN Scan)
* **Source IP:** `192.168.1.45` (Compromised Internal Host)
* **Target Subnet:** `192.168.1.0/24`
* **Wireshark Filter Used:** `tcp.flags.syn == 1 and tcp.flags.ack == 0`
* **Observation:** Host `192.168.1.45` sent over 1,200 TCP SYN packets across sequential ports (`21, 22, 23, 80, 443, 445, 3389`) within 10 seconds, followed immediately by `RST` packets—indicating an automated Nmap stealth scan for lateral movement.

---

### Finding 2: HTTP Command & Control (C2) Beaconing
* **Source IP:** `192.168.1.45`
* **Destination IP / Domain:** `185[.]220[.]101[.]4` (`c2-sync-node[.]net`) on Port `80`
* **Wireshark Filter Used:** `http.request.method == "POST" && ip.dst == 185.220.101.4`
* **Observation:** Outbound HTTP `POST` requests occurred consistently every **60 seconds** with an identical payload size (`248 bytes`) and a suspicious `User-Agent: Mozilla/4.0 (compatible; MSIE 6.0)`—a classic indicator of automated C2 heartbeat traffic.

---

### Finding 3: Suspicious DNS Queries (Potential Data Exfiltration)
* **Source IP:** `192.168.1.45`
* **Destination DNS Server:** `8.8.8.8` (Bypassing internal corporate DNS)
* **Wireshark Filter Used:** `dns.qry.name contains "tunnel-data"`
* **Observation:** Observed unusually long, Base64-encoded subdomain queries (e.g., `a3Jpc2hhbl9kYXRhX2V4Zmls.tunnel-data[.]org`) sent directly to an external resolver (`8.8.8.8`), indicating DNS tunneling to exfiltrate sensitive data.

---

## 4. Network Security Posture Recommendations
1. **Enforce Internal DNS & Block External Resolvers:** Configure perimeter firewalls to block outbound UDP/TCP port `53` traffic except from authorized internal DNS servers to prevent DNS tunneling.
2. **Block Malicious C2 Infrastructure:** Add `185[.]220[.]101[.]4` and `c2-sync-node[.]net` to firewall and web proxy blocklists immediately.
3. **Implement Network Segmentation & IPS:** Deploy an Intrusion Prevention System (IPS) and micro-segmentation to detect and block internal port scanning (`SYN` floods/reconnaissance) between workstations.
4. **Isolate & Remediate Compromised Host:** Quarantine `192.168.1.45` via EDR, investigate running processes, and remove any persistence mechanisms.
5. **Enforce Encrypted & Inspected Traffic:** Restrict legacy HTTP traffic and enable TLS inspection on egress web proxies to detect anomalous beaconing intervals.
