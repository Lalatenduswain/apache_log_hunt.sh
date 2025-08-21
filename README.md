# 🛡️ Apache Log Hunt – Suspicious Activity Scanner  
📌 **Repository:** [apache_log_hunt.sh](https://github.com/Lalatenduswain/apache_log_hunt.sh)  
👤 **Author:** [Lalatendu Swain](https://github.com/Lalatenduswain)  

---

## 📌 Features  
The **`apache_log_hunt.sh`** script is a security auditing tool designed for **Apache (httpd)** servers on CentOS/RHEL-based systems. It helps administrators quickly detect and analyze suspicious activity such as:

- ✅ SQL Injection attempts (`' or 1=1`, `UNION SELECT`, etc.)  
- ✅ Cross-Site Scripting (XSS) patterns (`<script>`, `alert()`)  
- ✅ Local/Remote File Inclusion (LFI/RFI) attacks (`../etc/passwd`, `php://input`, `data://`)  
- ✅ Command Injection attempts (`; ls`, `&& whoami`)  
- ✅ Auth & brute-force failures (`login failed`, `unauthorized`, `forbidden`)  
- ✅ Server issues (timeouts, script errors, broken pipe, too many connections)  
- ✅ Detects HTTP **4xx/5xx** errors (client & server errors)  
- ✅ Shows **Top IPs, URIs, and User-Agents** causing errors  
- ✅ Optional **GeoIP lookup** for top offenders  
- ✅ Supports **rotated & compressed logs** (`.gz`)  
- ✅ Ability to scan the **last N minutes** or **only today’s logs**  
- ✅ Focused scan for **specific attacker IPs**  

---

## 📖 Installation Guide  

### 🔧 Prerequisites  
Make sure your server has the following installed:  

- 🐧 **Linux OS**: CentOS/RHEL 8 (or compatible, works on most distros with Apache)  
- 🌐 **Apache (httpd)** logs located in `/var/log/httpd/` (default for CentOS/RHEL)  
- 📦 Required packages:  
  ```bash
  sudo yum install -y gzip awk gawk
  ```
- (Optional for GeoIP lookup):  
  ```bash
  sudo yum install -y geoip geoip-devel GeoIP-data
  ```
- Ensure you run the script with **sudo/root privileges** (since Apache logs require elevated access).  

---

### 🚀 Installation  

1. **Clone the repository**  
   ```bash
   git clone https://github.com/Lalatenduswain/apache_log_hunt.sh
   cd apache_log_hunt.sh
   ```

2. **Make script executable**  
   ```bash
   chmod +x apache_log_hunt.sh
   ```

3. **Run the scanner**  
   - Full scan of all logs:  
     ```bash
     sudo ./apache_log_hunt.sh
     ```
   - Scan last 2 hours & focus on specific attacker IPs:  
     ```bash
     sudo ./apache_log_hunt.sh -m 120 -a "54.179.156.222,3.10.160.87"
     ```
   - Scan today’s logs only:  
     ```bash
     sudo ./apache_log_hunt.sh --today
     ```

4. **Output**  
   Results are saved in:  
   ```
   /tmp/apache_log_audit_YYYY-MM-DD_HH-MM-SS.log
   ```

---

## 📂 Script Explanation  

- **`apache_log_hunt.sh`** works by scanning Apache **access** and **error logs** for suspicious patterns.  
- It automatically handles **plain logs** and **rotated/compressed logs** (`.gz`).  
- Patterns cover **SQLi, XSS, LFI/RFI, command injection, brute-force** and other anomalies.  
- Provides **summaries of top offenders (IPs, URIs, User-Agents)**.  
- Optionally highlights **specific IP addresses** that you want to track.  
- Can filter by **time window** (`-m MINUTES`) or **only today’s traffic**.  

---

## ⚡ Example Use Cases  

- 🔍 Investigate a suspicious SQL injection attempt reported in your alerts.  
- 📊 Generate a quick security report for the last 24 hours.  
- 🚫 Identify and block malicious IPs with repeated attacks.  
- 🛡️ Proactively monitor web application logs for intrusion attempts.  

---

## ⚠️ Disclaimer | Running the Script  

**Author:** Lalatendu Swain | [GitHub](https://github.com/Lalatenduswain) | [Website](https://blog.lalatendu.info/)  

This script is provided as-is and may require modifications or updates based on your specific environment and requirements.  
Use it at your own risk. The authors of the script are not liable for any damages or issues caused by its usage.  

---

## 💖 Support & Donations  

If you find this script useful and want to show your appreciation, you can donate via:  

👉 [Buy Me a Coffee](https://www.buymeacoffee.com/lalatendu.swain)  

---

## 🛠️ Support or Contact  

Encountering issues? Don’t hesitate to submit an issue on our [GitHub Issues Page](https://github.com/Lalatenduswain/apache_log_hunt.sh/issues).  

---
