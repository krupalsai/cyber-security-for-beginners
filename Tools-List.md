# 🛠️ Cyber Security Tools for Beginners

Here are essential tools used in cyber security. Start with the free and beginner-friendly ones.

---

## 🔍 Reconnaissance & Scanning

| Tool | Purpose | Level |
|------|---------|-------|
| **Nmap** | Network scanner — finds open ports and services | Beginner |
| **Shodan** | Search engine for internet-connected devices | Beginner |
| **Maltego** | Visual link analysis and OSINT | Intermediate |
| **theHarvester** | Email/domain information gathering | Beginner |

### Nmap Quick Start
```bash
nmap -sV 192.168.1.1        # Scan a host and detect versions
nmap -p 80,443 google.com   # Scan specific ports
nmap -A 192.168.1.0/24      # Aggressive scan of whole network
```

---

## 🌐 Web Application Testing

| Tool | Purpose | Level |
|------|---------|-------|
| **Burp Suite** | Web proxy for intercepting HTTP requests | Beginner |
| **OWASP ZAP** | Free web vulnerability scanner | Beginner |
| **Nikto** | Web server scanner | Beginner |
| **SQLmap** | Automated SQL injection testing | Intermediate |
| **Dirb / Gobuster** | Directory brute-forcing on web servers | Beginner |

---

## 🔐 Password Tools

| Tool | Purpose | Level |
|------|---------|-------|
| **Hashcat** | Password hash cracking (GPU-powered) | Intermediate |
| **John the Ripper** | Classic password cracker | Beginner |
| **Hydra** | Online brute-force attack tool | Intermediate |
| **CrackStation** | Online hash lookup (educational) | Beginner |

---

## 📡 Network Analysis

| Tool | Purpose | Level |
|------|---------|-------|
| **Wireshark** | Capture and analyze network packets | Beginner |
| **tcpdump** | Command-line packet capture | Intermediate |
| **Netcat** | Networking Swiss Army knife | Intermediate |

---

## 💻 Exploitation Frameworks

| Tool | Purpose | Level |
|------|---------|-------|
| **Metasploit** | Most popular exploitation framework | Intermediate |
| **BeEF** | Browser exploitation framework | Intermediate |

---

## 🖥️ Operating Systems for Security

| OS | Purpose |
|----|---------|
| **Kali Linux** | Most popular security distro — comes pre-installed with tools |
| **Parrot OS** | Lighter alternative to Kali |
| **BlackArch** | Arch-based, massive tool collection |

> 💡 Beginners: Install **Kali Linux** on VirtualBox. It's free and safe to practice on.

---

## 🕵️ OSINT Tools

| Tool | Purpose |
|------|---------|
| **Google Dorking** | Advanced Google search for sensitive info |
| **OSINT Framework** | Website listing hundreds of OSINT tools |
| **IntelTechniques** | Tools for open-source intelligence |

---

## ✅ Where to Practice Legally

- [TryHackMe](https://tryhackme.com) — Best for beginners, guided paths
- [HackTheBox](https://hackthebox.com) — More challenging, realistic labs
- [PicoCTF](https://picoctf.org) — Beginner CTF challenges
- [OverTheWire](https://overthewire.org) — Linux + security wargames

---
> ⚠️ Always use these tools only on systems you own or have explicit permission to test.
