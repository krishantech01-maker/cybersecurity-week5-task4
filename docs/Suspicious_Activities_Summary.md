# Summary of Suspicious Network Activities & IoCs

**Task:** Week 5 - Task 4 (Advanced Network Traffic Analysis)  

## 1. Detected Anomalies Table

| Alert ID | Activity Type | Protocol | Source IP | Destination IP / Domain | Key Indicators | Severity |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **NET-01** | Internal Port Scan | TCP | `192.168.1.45` | `192.168.1.0/24` | 1,200+ SYN packets in <10s | **Medium** |
| **NET-02** | C2 Beaconing | HTTP | `192.168.1.45` | `185[.]220[.]101[.]4` (`c2-sync-node[.]net`) | Fixed 60s POST interval | **Critical** |
| **NET-03** | DNS Tunneling | DNS | `192.168.1.45` | `8.8.8.8` (`tunnel-data[.]org`) | Long encoded subdomains | **High** |

---

## 2. Useful `tcpdump` & Wireshark Commands Used

* **Capture suspicious HTTP traffic via `tcpdump`:**
  ```bash
  tcpdump -i eth0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' -w http_payloads.pcap
  ```
* **Detect SYN Scan packets in Wireshark:**
  ```text
  tcp.flags.syn == 1 and tcp.flags.ack == 0
  ```
* **Isolate external DNS queries bypassing local DNS:**
  ```text
  dns and ip.dst != 192.168.1.1
  ```
