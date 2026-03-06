# Recon Automation Framework v3

A modular Python reconnaissance framework for authorized security testing.

## Features

- Subdomain discovery via crt.sh
- DNS resolution (A / AAAA / CNAME)
- TCP port scanning
- HTTP/HTTPS probing
- JSON + CSV reporting
- Clean modular architecture
- Aggressive colored terminal banner

## Installation

```bash

pip install -r requirements.txt

┌──(kali㉿kali)-
└─$sudo python3 recon.py               
usage: recon.py [-h] -d DOMAIN [-o OUTPUT] [--csv CSV] [-t THREADS] [--timeout TIMEOUT] [--ports PORTS]
RUN AS ROOT
sudo python3 recon.py -d example.com
