# SubFinder

Fast threaded Python tool for DNS-based subdomain enumeration.

SubFinder is a lightweight reconnaissance tool that discovers subdomains of a 
target domain using a wordlist and DNS resolution. It is designed for learning 
penetration testing workflows and building custom cybersecurity tools.

⚠️ **For authorized security testing only.**

---

# Features

• Multithreaded subdomain scanning
• DNS resolution using Python socket library
• Wildcard DNS detection
• Scan progress bar with ETA
• Automatic results storage
• Scan history tracking
• Clean CLI interface

---

# Installation

Clone the repository:

```
git clone https://github.com/omprakash-elph/subdomain-finder.git
cd subdomain-finder
```

No external Python libraries are required.

---

# Usage

Run the tool:

```
python3 subdomain-finder.py
```

Example interaction:

```
[INPUT] Target domain  : microsoft.com
[INPUT] Wordlist path  : wordlist.txt
[INPUT] Thread count   : 20
```

---

# Example Output

```
[FOUND] api.microsoft.com        → 20.76.201.171
[FOUND] login.microsoft.com      → 20.190.146.33
[FOUND] portal.microsoft.com     → 150.171.73.13
[FOUND] support.microsoft.com    → 13.107.246.58
```

Results are saved in the `results/` folder.

---

# Project Structure

```
subdomain-finder
│
├── subdomain-finder.py
├── wordlist.txt
├── results/
└── README.md
```

---

# How It Works

The tool performs **active DNS reconnaissance**:

1. Loads a list of possible subdomains
2. Combines each word with the target domain
3. Sends DNS queries using Python sockets
4. Records valid subdomains and their IP addresses
5. Saves results for later analysis

---

# Learning Purpose

This project is part of a cybersecurity learning path for understanding:

• Reconnaissance techniques
• DNS infrastructure
• Multithreading in Python
• Building custom penetration testing tools

---

# Author

Om Prakash

Cybersecurity learner focused on ethical hacking and security tool development.

---

# Disclaimer

This tool is intended **only for educational purposes and authorized penetration testing**.
Do not scan systems without explicit permission.
