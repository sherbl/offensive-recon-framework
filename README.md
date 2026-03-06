# Recon Automation Framework v3



<img width="704" height="737" alt="Screenshot_41" src="https://github.com/user-attachments/assets/eb8971c5-d547-4a93-879b-53d327968933" />



🚀 Just released a new project: **Offensive Recon Framework**

I’ve been working on a reconnaissance automation tool designed to help map the **attack surface of a target domain**.

The framework performs:

• Subdomain discovery
• DNS intelligence analysis
• Port scanning
• HTTP service discovery
• Infrastructure mapping
• Attack surface classification
• Target prioritization

The goal of this project is to automate the **initial reconnaissance phase of penetration testing** and quickly identify potentially interesting targets.

Built in **Python** and designed with a modular architecture.

🔗 GitHub:
https://github.com/sherbl/offensive-recon-framework

Feedback and ideas are always welcome.


## Installation

```bash

pip install -r requirements.txt

┌──(kali㉿kali)-
└─$sudo python3 recon.py               
usage: recon.py [-h] -d DOMAIN [-o OUTPUT] [--csv CSV] [-t THREADS] [--timeout TIMEOUT] [--ports PORTS]

RUN AS ROOT
sudo python3 recon.py -d example.com
