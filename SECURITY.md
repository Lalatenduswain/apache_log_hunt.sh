# 🔐 Security Policy for apache_log_hunt.sh

We take security seriously. If you discover a **security vulnerability** in this project, please report it responsibly.

---

## 📢 Reporting a Vulnerability

- **Do NOT open a public GitHub issue** for security problems.  
- Instead, email me directly:  
  📧 `security@example.com` (replace with your actual contact email)  
- Include details:  
  - Vulnerability description  
  - Steps to reproduce  
  - Potential impact  
  - Suggested fix (if any)

---

## 🚨 Supported Versions

We currently support the **latest version** of `apache_log_hunt.sh`.  
Older versions are not guaranteed to receive fixes.

| Version   | Supported          |
|-----------|--------------------|
| Latest    | ✅ Yes             |
| Older     | ❌ No              |

---

## 🛠️ Responsible Disclosure

Please give us **at least 90 days** to investigate and fix the issue before public disclosure.  
We will credit you in the changelog if you wish.  

---

## ✅ Security Best Practices (for users)

- Always run the script with **sudo/root** since Apache logs need elevated permissions.  
- Keep your server updated:  
  ```bash
  sudo yum update -y
  ```
- Install **fail2ban** or similar tools to block repeated attackers.  
- Regularly review output of `apache_log_hunt.sh` to spot anomalies.  

---

**Maintainer:** [Lalatendu Swain](https://github.com/Lalatenduswain)  
