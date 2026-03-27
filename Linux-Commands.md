# 🐧 Essential Linux Commands for Cyber Security

Linux is the primary OS for security professionals. Master these commands!

---

## 📁 File & Directory Navigation

```bash
pwd                    # Show current directory
ls                     # List files
ls -la                 # List all files with details (including hidden)
cd /home/user          # Change directory
cd ..                  # Go up one level
mkdir myfolder         # Create a directory
rm file.txt            # Delete a file
rm -rf folder/         # Delete folder and everything inside (careful!)
cp file.txt /tmp/      # Copy a file
mv file.txt /tmp/      # Move or rename a file
find / -name "*.log"   # Find files by name
```

---

## 📄 Viewing & Editing Files

```bash
cat file.txt           # Display file contents
less file.txt          # View file page by page
head -20 file.txt      # Show first 20 lines
tail -20 file.txt      # Show last 20 lines
grep "error" log.txt   # Search for text in a file
grep -r "password" ./  # Search recursively in all files
nano file.txt          # Simple text editor (beginner-friendly)
vim file.txt           # Advanced editor (press i to type, :wq to save)
```

---

## 👤 Users & Permissions

```bash
whoami                 # Show current user
id                     # Show user ID and group info
sudo command           # Run command as admin
su - username          # Switch to another user
passwd                 # Change your password
adduser newuser        # Create a new user
chmod 755 file.sh      # Change file permissions
chown user:group file  # Change file owner
ls -l                  # See permissions of files
```

### Permission Numbers Explained
```
7 = rwx (read + write + execute)
6 = rw- (read + write)
5 = r-x (read + execute)
4 = r-- (read only)
0 = --- (no permissions)
```

---

## 🌐 Networking Commands

```bash
ip a                   # Show IP addresses (modern)
ifconfig               # Show network interfaces (older)
ping google.com        # Test connectivity
nslookup google.com    # DNS lookup
dig google.com         # Detailed DNS lookup
traceroute google.com  # Show path packets take
netstat -tuln          # Show open ports and connections
ss -tuln               # Modern version of netstat
curl https://site.com  # Fetch a URL from terminal
wget https://file.com  # Download a file
```

---

## ⚙️ Processes & System

```bash
ps aux                 # List all running processes
top                    # Live process monitor
htop                   # Prettier process monitor (install first)
kill 1234              # Kill process by ID
kill -9 1234           # Force kill process
df -h                  # Disk usage
du -sh folder/         # Size of a folder
free -h                # RAM usage
uname -a               # System info
uptime                 # How long system has been running
history                # Show command history
```

---

## 📦 Package Management (Debian/Kali/Ubuntu)

```bash
sudo apt update              # Update package list
sudo apt upgrade             # Upgrade all packages
sudo apt install nmap        # Install a package
sudo apt remove nmap         # Remove a package
sudo apt search keyword      # Search for a package
```

---

## 🔐 Security-Specific Commands

```bash
ssh user@192.168.1.5         # Connect to remote machine
ssh-keygen                   # Generate SSH key pair
scp file.txt user@host:/tmp/ # Securely copy file to remote host
nmap -sV 192.168.1.1         # Scan open ports on a host
nc -lvnp 4444                # Listen on port 4444 (Netcat)
nc 192.168.1.5 4444          # Connect to port 4444
strings binary_file          # Extract readable strings from a file
file unknown_file            # Identify file type
xxd file.bin | head          # View file in hex
base64 -d encoded.txt        # Decode base64 string
```

---

## 🗜️ Compression & Archives

```bash
tar -czf archive.tar.gz folder/  # Create compressed archive
tar -xzf archive.tar.gz          # Extract archive
unzip file.zip                    # Unzip file
zip -r output.zip folder/         # Zip a folder
```

---

## 🎯 Tips for Beginners

- Use `man command` to read the manual for any command (e.g., `man ls`)
- Use `command --help` for quick help
- Use `Tab` key to auto-complete commands and file names
- Use `Ctrl+C` to stop a running command
- Use `Ctrl+Z` to pause a process
- Use `!!` to repeat the last command

---
> 💡 Practice daily on TryHackMe's Linux rooms or OverTheWire's Bandit wargame!
