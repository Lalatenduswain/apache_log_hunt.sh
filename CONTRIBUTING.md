# Contributing to apache_log_hunt.sh 🛡️

First of all, thank you 🙌 for considering contributing to **apache_log_hunt.sh**!  
Your contributions help make this project more secure, stable, and useful for everyone.

---

## 📌 How Can You Contribute?

- 🐛 **Report Bugs** → Open an issue describing the problem and how to reproduce it.  
- 💡 **Suggest Features** → Open an issue with `[Feature Request]` in the title.  
- 🔧 **Submit Code Improvements** → Fork the repo, make changes, and open a pull request.  
- 📖 **Improve Documentation** → Typos, examples, or better explanations are always welcome.  

---

## 🛠️ Development Workflow

1. **Fork the repository** to your GitHub account.  
2. **Clone your fork** locally:  
   ```bash
   git clone https://github.com/<your-username>/apache_log_hunt.sh
   cd apache_log_hunt.sh
   ```
3. **Create a new branch** for your feature/fix:  
   ```bash
   git checkout -b feature/my-new-feature
   ```
4. **Make your changes** (code, docs, etc.).  
5. **Test your script** locally before submitting.  
6. **Commit with a meaningful message**:  
   ```bash
   git commit -m "Add: suspicious pattern detection for XXE attacks"
   ```
7. **Push your branch** to GitHub:  
   ```bash
   git push origin feature/my-new-feature
   ```
8. **Open a Pull Request (PR)** → Describe clearly what you changed and why.  

---

## 📏 Coding Standards

- Follow **bash best practices** (`set -euo pipefail`).  
- Use **shellcheck** (`sudo yum install -y ShellCheck` or `apt install shellcheck`) to lint scripts.  
- Keep comments concise but clear.  
- Don’t commit sensitive information (paths, IPs, API keys).  

---

## ✅ Pull Request Checklist

Before submitting your PR:
- [ ] My code runs without errors.  
- [ ] I’ve tested on CentOS/RHEL (or equivalent Apache setup).  
- [ ] I’ve updated README/docs if needed.  
- [ ] I’ve added tests or examples if applicable.  

---

## ❤️ Code of Conduct

Be respectful, professional, and helpful. We’re building a security tool for the community — let’s keep it positive.

---

**Maintainer:** [Lalatendu Swain](https://github.com/Lalatenduswain)  
