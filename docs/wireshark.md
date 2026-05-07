Wireshark is insanely feature-rich—but most people only scratch the surface. Here’s a **clean, no-BS breakdown of its capabilities**, grouped in a way that actually reflects how you’d use it.

---

# 1. Packet Capture Capabilities

This is the core.

* Capture live traffic from:

  * Wi-Fi, Ethernet, Bluetooth (limited), USB (advanced setups)
* Promiscuous mode (capture all packets, not just yours)
* Monitor mode (for wireless packet sniffing, if supported)
* Remote capture (from another machine)
* Loopback capture (see traffic from your own PC apps)

**Control features:**

* Start/stop capture anytime
* Capture filters (BPF syntax) → filter *before* data is recorded
  Example:

  ```
  port 80
  host 192.168.1.1
  ```

---

# 2. Deep Packet Inspection (DPI)

This is where Wireshark becomes powerful.

* Dissects **1000+ protocols**:

  * HTTP, HTTPS, DNS, TCP, UDP, TLS, FTP, ARP, etc.

* Shows packet in 3 layers:

  * Packet list (summary)
  * Packet details (protocol tree)
  * Raw bytes (hex + ASCII)

* Automatic protocol decoding
  (Even if running on non-standard ports)

---

# 3. Advanced Filtering System

Arguably Wireshark’s strongest feature.

### Display Filters (post-capture)

More powerful than capture filters:

```
http.request
ip.addr == 192.168.0.1
tcp.flags.syn == 1
dns
```

* Supports logical operators (`and`, `or`, `not`)
* Color highlighting rules
* Filter auto-suggestions (huge productivity boost)

---

# 4. Stream Reconstruction

This is where things get interesting.

* Reassemble entire conversations:

  * TCP streams (e.g., full HTTP request/response)
  * Follow → TCP Stream / HTTP Stream

* Lets you:

  * Read raw API calls
  * Extract form data
  * See full payloads

---

# 5. Decryption Support (when possible)

Not magic—but powerful if configured.

* TLS/SSL decryption (with keys)
* WPA/WPA2 Wi-Fi decryption (with passphrase + handshake)
* Decrypt protocols like:

  * HTTPS
  * SSH (limited scenarios)

---

# 6. Protocol Analysis & Statistics

This is where Wireshark shifts from raw data → insights.

### Built-in stats tools:

* Protocol Hierarchy (traffic breakdown)
* Conversations (who talks to whom)
* Endpoints (IP-level analysis)
* IO Graphs (traffic over time)
* Flow Graph (visual packet flow)

---

# 7. Expert Information System

Wireshark flags issues automatically.

* Detects:

  * Retransmissions
  * Packet loss
  * Duplicate ACKs
  * Malformed packets

* Categorizes into:

  * Notes
  * Warnings
  * Errors

---

# 8. Coloring & Visualization

Not just aesthetic—helps you think faster.

* Default coloring rules:

  * TCP errors (red)
  * DNS (blue)
  * HTTP (green)

* Custom color rules:

  * Highlight suspicious traffic
  * Mark specific IPs or ports

---

# 9. File Handling & Exporting

* Save captures as:

  * `.pcap`, `.pcapng`
* Export:

  * Specific packets
  * Objects (images, files from HTTP)
* Merge multiple captures
* Split large capture files

---

# 10. Name Resolution

Makes raw IPs human-readable.

* DNS resolution (IP → domain)
* MAC address resolution (vendor lookup)
* Transport name resolution (port → service)

---

# 11. Customization & Extensibility

Wireshark is extremely customizable.

* Custom columns (e.g., latency, IPs)
* Custom filters & profiles
* Lua scripting support:

  * Write your own protocol dissectors
  * Automate analysis

---

# 12. VoIP & Multimedia Analysis

Surprisingly niche but powerful.

* Analyze SIP calls
* Play RTP streams (audio playback)
* Detect jitter, latency, packet loss in calls

---

# 13. Security Analysis Features

Used heavily in cybersecurity.

* Detect:

  * Suspicious traffic
  * Port scans
  * ARP spoofing
* Analyze malware communication patterns
* Inspect payloads for anomalies

---

# 14. Command-Line Integration

Wireshark isn’t just GUI.

* TShark

  * CLI version of Wireshark
  * Useful for automation, servers, pipelines

Example:

```
tshark -i eth0 -f "port 80"
```

---

# 15. Cross-Platform Support

* Windows (most common for beginners)
* Linux (preferred in security roles)
* macOS

---

# Reality Check

Wireshark’s features are insane—but:

* 80% of people only use:

  * basic capture
  * simple filters
* The real edge comes from:

  * combining filters + stream analysis + protocol understanding

---

If you want to actually leverage it (not just list features), I can show you:

* how to analyze a **login API call**
* or how to use it for **internship-level security/network projects**
  That’s where this tool goes from “cool” → “career leverage.”
