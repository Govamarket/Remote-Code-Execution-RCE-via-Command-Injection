# Remote-Code-Execution-RCE-via-Command-Injection

<div align="center">

# 🔥 Remote Code Execution (RCE) via Command Injection

[![Severity](https://img.shields.io/badge/Severity-Critical-red?style=for-the-badge)](https://nvd.nist.gov/vuln-metrics/cvss)
[![CVSS](https://img.shields.io/badge/CVSS-9.8-red?style=for-the-badge)](https://nvd.nist.gov/vuln-metrics/cvss)
[![OWASP](https://img.shields.io/badge/OWASP-A03%3A2021-orange?style=for-the-badge)](https://owasp.org/Top10/A03_2021-Injection/)
[![CWE](https://img.shields.io/badge/CWE-78-blue?style=for-the-badge)](https://cwe.mitre.org/data/definitions/78.html)
[![Type](https://img.shields.io/badge/Type-Command%20Injection-purple?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-Educational%20Only-green?style=for-the-badge)]()

> ⚠️ **All testing was performed in an isolated, intentionally vulnerable lab environment.**
> **For educational purposes only. Do not attempt on systems you do not own or have explicit permission to test.**

</div>

---

## 📖 Table of Contents

- [Summary](#-summary)
- [Lab Environment](#-lab-environment)
- [Vulnerability Details](#-vulnerability-details)
- [Severity Rating](#-severity-rating)
- [Exploitation Process](#-exploitation-process)
- [Impact](#-impact)
- [Remedy & Mitigation](#-remedy--mitigation)
- [Remediation Summary](#-remediation-summary)
- [Key Takeaways](#-key-takeaways)
- [Skills Demonstrated](#-skills-demonstrated)
- [References](#-references)
- [Author](#-author)

---

## 📌 Summary

This project documents a **Command Injection vulnerability** that leads to **Remote Code Execution (RCE)** in a web application.

The application insecurely passes user-supplied input directly into a system shell — allowing an attacker to execute arbitrary commands on the server with no authentication required. This represents one of the most critical vulnerability classes in web application security.

---

##  Lab Environment

| Property | Detail |
|----------|--------|
| **Platform** | Simulated intentionally vulnerable web application |
| **OS** | Linux-based backend |
| **Interface** | Exposed command execution endpoint accepting raw user input |
| **Context** | Controlled lab — isolated from production systems |

---

## 🚨 Vulnerability Details

### Root Cause

The application directly passes user input into a system shell without any sanitization:

```python
import os
os.system(user_input)  # VULNERABLE: shell interprets all metacharacters
```

When a shell receives input like `whoami; cat /etc/passwd`, it treats `;` as a command separator and executes **both** commands. The application never intended this — but the shell doesn't know that.

### Shell Metacharacters That Enable Injection

| Character | Behaviour |
|-----------|-----------|
| `;` | Run next command regardless of result |
| `&&` | Run next command only if previous succeeded |
| `\|\|` | Run next command only if previous failed |
| `\|` | Pipe output of first command into second |
| `` ` `` or `$()` | Execute in subshell and substitute output |
| `\n` | Newline — some parsers treat as command separator |

---

## 🔴 Severity Rating

| Attribute | Detail |
|-----------|--------|
| **Severity** | 🔴 Critical |
| **CVSS Score** | 9.8 / 10 |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) — Improper Neutralization of Special Elements in an OS Command |
| **OWASP** | [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/) |

### Why Critical?

- No authentication required to trigger the vulnerability
- Exploitation requires no special tools — a browser is sufficient
- A successful attack yields **full server compromise**
- Sensitive system files are directly readable
- Attackers can pivot to privilege escalation and lateral movement

---

## 🔓 Exploitation Process

### ✅ Step 1 — Confirm Command Execution

```bash
whoami
pwd
ls
```

> **Result:** Confirmed user input is executed directly on the server with zero filtering.
<div>
  <img width="941" height="218" alt="rce" src="https://github.com/user-attachments/assets/470cdb11-52fd-4ca6-9439-91e56ace3e11" />

</div>
---

### ✅ Step 2 — Command Injection via Shell Operators

```bash
whoami && pwd
whoami || pwd
whoami && ls -la
```

> **Result:** Multiple commands chained successfully. No input sanitization present.

---

### ✅ Step 3 — File System Enumeration

```bash
ls -la
find / -name "*.conf" 2>/dev/null
```

> **Result:** Files and directories accessible to the running process enumerated.

---

### ✅ Step 4 — Sensitive File Access

```bash
cat /etc/passwd
```

> **Result:** System user account data retrieved — direct information disclosure.

---

### ✅ Step 5 — Full System Enumeration

```bash
uname -a        # OS and kernel version
id              # Current user and group privileges
ps aux          # All running processes
netstat -tulpn  # Active network connections and listening ports
```

> **Result:** Complete picture of OS, kernel, privileges, processes, and network topology obtained.

---

##  Impact

| Impact Area | Description |
|-------------|-------------|
| **Arbitrary Command Execution** | Run any OS command as the application user |
| **Data Exfiltration** | Read `/etc/passwd`, config files, environment variables, secrets |
| **System Enumeration** | Map OS, kernel, network layout, and running services |
| **Privilege Escalation** | Leverage misconfigurations to gain root access |
| **Persistence** | Plant backdoors, malicious cron jobs, or reverse shells |
| **Full Compromise** | Complete takeover of server and all hosted data |

---

##  Remedy & Mitigation

### 1. Avoid Shell Execution ← : Highest Priority

Never pass user input to a shell. Use parameterized system calls:

```python
# VULNERABLE — shell interprets metacharacters
import os
os.system(f"ping {user_input}")

# SECURE — list form bypasses shell entirely
import subprocess
subprocess.run(["ping", "-c", "1", user_input], capture_output=True)
```

The key difference: the list form passes arguments directly to the OS kernel — **no shell is involved**, so metacharacters are treated as literal strings, not syntax.

---

### 2. Input Whitelisting

Reject everything that is not on an explicitly approved list:

```python
ALLOWED_COMMANDS = {"whoami", "pwd", "ls"}

if user_input not in ALLOWED_COMMANDS:
    raise ValueError("Command not permitted.")
```

>  **Blacklisting is not sufficient.** Blocking `;`, `&&`, etc. can always be bypassed with encoding tricks or alternative separators. Always whitelist.

---

### 3. Least Privilege

Run the application as a low-privilege system user, never as root:

```bash
# Run service as www-data, not root
sudo -u www-data python3 app.py
```

This limits the blast radius — even if injection succeeds, the attacker inherits only the app's restricted permissions, not full system access.

---

### 4. Sandboxing & Isolation

Isolate command execution using containers or restricted environments:

```bash
# Docker container with no extra Linux capabilities
docker run --rm \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --read-only \
  myapp
```

---

### 5. Web Application Firewall (WAF)

Deploy a WAF to detect and block common injection payloads at the network layer. This is a **defense-in-depth** measure — it should complement, not replace, secure coding practices.

---

### 6. Output Filtering & Error Handling

Never expose raw command output or stack traces to the end user:

```python
try:
    result = subprocess.run(["ls", "-la"], capture_output=True, text=True)
    return sanitize(result.stdout)  # Strip sensitive paths, usernames, etc.
except Exception:
    logger.error("Command execution error", exc_info=True)
    return "An error occurred."  # Generic message — no internals leaked
```

---

##  Remediation Summary

| Control | Priority | Effort |
|---------|----------|--------|
| Replace shell execution with parameterized calls | 🔴 Critical | Low |
| Input whitelisting | 🔴 Critical | Low |
| Least privilege (run as non-root) | 🟠 High | Low |
| Sandboxing / containerization | 🟠 High | Medium |
| WAF deployment | 🟡 Medium | Medium |
| Output filtering & error sanitization | 🟡 Medium | Low |

---

##  Key Points

- **Never trust user input** — treat all external data as hostile until proven otherwise
- **Blacklisting fails** — attackers always find character encoding bypasses; always whitelist
- **Shell execution + user input = dangerous** — avoid the combination entirely
- **Small misconfigurations lead to full compromise** — the gap between "minor flaw" and "critical RCE" is often just one unsanitized input
- **Defense-in-depth** — layer multiple controls; no single fix is sufficient on its own

---

##  Skills Demonstrated

- Command Injection Testing & Exploitation Analysis
- Linux System Enumeration
- Vulnerability Impact Assessment
- CVSS Severity Scoring
- CWE / OWASP Classification
- Secure Code Review
- Professional Security Reporting

---

##  References

- [OWASP: OS Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP Top 10 — A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [PortSwigger Web Security Academy: OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [NIST NVD — CVSS v3.1 Calculator](https://nvd.nist.gov/vuln-metrics/cvss)
- [Python subprocess documentation](https://docs.python.org/3/library/subprocess.html)

---

* Next Steps: Advanced RCE filter bypass · Reverse shells · Privilege escalation · Web exploitation chaining*

</div>
