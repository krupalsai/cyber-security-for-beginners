# 🌐 Networking Basics for Cyber Security

Understanding networks is the #1 foundation for cyber security. Here's what you need to know.

---

## What is a Network?

A **network** is a group of computers connected together to share data.  
The internet is just a giant network of networks!

---

## Key Networking Concepts

### 🔹 IP Address
- Every device on a network has a unique **IP address**
- Example: `192.168.1.5`
- **IPv4** — 4 numbers (most common): `192.168.0.1`
- **IPv6** — newer, longer format: `2001:0db8:85a3::8a2e:0370:7334`

### 🔹 MAC Address
- A **hardware address** burned into your network card
- Looks like: `00:1A:2B:3C:4D:5E`
- Unlike IP, MAC doesn't change

### 🔹 DNS (Domain Name System)
- Converts domain names to IP addresses
- Example: `google.com` → `142.250.182.46`
- Think of it as the internet's **phone book**

### 🔹 Ports
- Ports are like **doors** on a computer
- Common ports to remember:

| Port | Service |
|------|---------|
| 22 | SSH (remote login) |
| 80 | HTTP (web) |
| 443 | HTTPS (secure web) |
| 21 | FTP (file transfer) |
| 53 | DNS |
| 3389 | RDP (Windows remote) |

### 🔹 Protocols
- **TCP** — Reliable, checks that data arrives (used for web, email)
- **UDP** — Fast, no error-checking (used for video, gaming)
- **HTTP/HTTPS** — Web browsing
- **FTP** — File transfer
- **SSH** — Secure remote access

---

## OSI Model (7 Layers)

The OSI model explains how data travels through a network:

| Layer | Name | Example |
|-------|------|---------|
| 7 | Application | Browser, Email client |
| 6 | Presentation | Encryption, Compression |
| 5 | Session | Login sessions |
| 4 | Transport | TCP, UDP |
| 3 | Network | IP Addresses, Routing |
| 2 | Data Link | MAC Addresses |
| 1 | Physical | Cables, Wi-Fi signals |

> 💡 Memory trick: **"All People Seem To Need Data Processing"**

---

## Subnetting Basics

- **Subnet mask** defines which part of the IP is the network vs host
- Example: `192.168.1.0/24` means 256 addresses (`.0` to `.255`)
- `192.168.1.1` — Usually the router/gateway

---

## Common Network Devices

| Device | Role |
|--------|------|
| **Router** | Connects different networks (e.g., home to internet) |
| **Switch** | Connects devices within the same network |
| **Firewall** | Monitors and filters traffic |
| **Access Point** | Provides Wi-Fi connectivity |
| **Proxy** | Acts as middleman between user and internet |

---
> 💡 Practice: Open Command Prompt / Terminal and run `ipconfig` (Windows) or `ifconfig` / `ip a` (Linux) to see your own network details.
