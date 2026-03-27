# ⚔️ Common Cyber Attacks Explained

Learn how attackers think — so you can defend better.

---

## 1. 🎣 Phishing

**What it is:** Fake emails or websites that trick you into entering your credentials.

**Example:** You get an email saying "Your bank account is locked, click here to verify."  
The link goes to a fake bank website that steals your password.

**How to stay safe:**
- Always check the sender's email address
- Hover over links before clicking
- Use MFA (Multi-Factor Authentication)

---

## 2. 🦠 Malware

**What it is:** Malicious software installed on your device without your knowledge.

**Types:**
| Type | What it does |
|------|-------------|
| **Virus** | Attaches to files and spreads |
| **Worm** | Spreads on its own across networks |
| **Trojan** | Disguised as a useful program |
| **Ransomware** | Locks your files, demands money |
| **Spyware** | Records your activities secretly |
| **Adware** | Forces unwanted ads |

**How to stay safe:**
- Keep software updated
- Use a trusted antivirus
- Don't download files from unknown sources

---

## 3. 💥 DDoS (Distributed Denial of Service)

**What it is:** Flooding a server with millions of fake requests until it crashes.

**Example:** A game server gets attacked and nobody can play.

**How to stay safe (for admins):**
- Use a CDN (Cloudflare, etc.)
- Enable rate limiting
- Use a DDoS protection service

---

## 4. 🧑‍💻 SQL Injection

**What it is:** Inserting malicious SQL code into a website's login form to bypass authentication or steal data.

**Example:**
```
Username: admin' --
Password: anything
```
This can log into an account without knowing the password!

**How to stay safe:**
- Use parameterized queries
- Validate and sanitize all user inputs

---

## 5. 🪞 Man-in-the-Middle (MITM) Attack

**What it is:** Attacker secretly intercepts communication between two parties.

**Example:** You connect to fake Wi-Fi at a café — the attacker reads everything you send.

**How to stay safe:**
- Use HTTPS websites only
- Use a VPN on public Wi-Fi
- Don't ignore SSL certificate warnings

---

## 6. 🔑 Brute Force Attack

**What it is:** Trying thousands/millions of password combinations until one works.

**How to stay safe:**
- Use long, complex passwords
- Enable account lockout after failed attempts
- Use a password manager

---

## 7. 🎭 Social Engineering

**What it is:** Manipulating people (not machines) to give up information.

**Example:** Someone calls pretending to be IT support and asks for your password.

**How to stay safe:**
- Never share passwords — even with "IT support"
- Verify identities before sharing anything
- Train yourself and others to be suspicious

---

## 8. 🔓 Privilege Escalation

**What it is:** A hacker gains low-level access, then tricks the system into giving admin/root access.

**How to stay safe:**
- Apply principle of least privilege
- Keep systems patched and updated

---
> 💡 Remember: Most attacks exploit **human mistakes**, not just technical bugs.
