# CTF Write-Ups Collection

A comprehensive collection of detailed penetration testing write-ups from various Capture The Flag challenges. Each document provides thorough analysis of vulnerabilities, exploitation techniques, and privilege escalation methodologies.

## Contents

This repository contains professional security research documentation covering:

- **Network Enumeration** - Service discovery and reconnaissance techniques
- **Web Application Exploitation** - SQLi, LFI, command injection, file upload bypasses
- **Privilege Escalation** - Linux capabilities, sudo misconfigurations, PATH hijacking
- **Container Security** - Docker escape techniques and volume exploitation
- **Authentication Bypass** - 2FA circumvention, credential extraction, session manipulation
- **Reverse Engineering** - Binary analysis and system call exploitation

## Write-Ups

### The Many Faced God
Network reconnaissance through SMB enumeration, NFS share exploitation, Redis database access, rsync file retrieval, SSH key manipulation, and TeamCity privilege escalation via PATH hijacking.

**Key Techniques:** SMB/NFS enumeration, Redis exploitation, rsync abuse, TeamCity RCE

### Musa Troglodytarum
Web application analysis featuring hidden directory discovery, steganographic analysis for credential extraction, FTP brute-forcing, whitespace encoding decoding, and sudo vulnerability exploitation (CVE-2019-14287).

**Key Techniques:** Steganography, whitespace encoding, FTP exploitation, sudo CVE-2019-14287

### The Binding of Cyber
Sequential port probing across 900+ ports, NFS share mounting, password-protected archive cracking, SSH key-based authentication, and Linux capability exploitation via tar binary abuse.

**Key Techniques:** Extensive port scanning, NFS exploitation, capability abuse, tar privilege escalation

### Trickster
SMB password cracking, web application command injection via Base64 encoding bypass, SSH port forwarding with Socat, internal service access, and privilege escalation through PATH hijacking on a misconfigured sudo binary.

**Key Techniques:** SMB brute-force, command injection, Socat tunneling, PATH hijacking

### Fun with Functional
Haskell-based web application exploitation, file upload restriction bypass using language-specific reverse shells, SSH key extraction, Flask application abuse with sudo, and privilege escalation through FLASK_APP environment variable manipulation.

**Key Techniques:** File upload exploitation, Haskell reverse shell, Flask RCE, sudo env abuse

### Patience
Cookie-based SQL injection with WAF bypass via hexadecimal encoding, web shell deployment, reverse shell establishment, SSH tunneling to internal Gitea service, 2FA bypass through database manipulation, webhook abuse, and Docker volume privilege escalation.

**Key Techniques:** SQLi with encoding, WAF bypass, Gitea exploitation, 2FA bypass, Docker volume escape

### TekPedago
Local File Inclusion via PHP filter wrappers, Apache log poisoning for RCE, sudo privilege escalation through /usr/bin/env, Docker container detection, cron job exploitation for container escape, and host system compromise.

**Key Techniques:** LFI exploitation, log poisoning, container escape, cron job abuse

## Technical Skills Demonstrated

**Web Exploitation:**
- SQL Injection (UNION-based, blind, error-based)
- Local File Inclusion with PHP filters
- Remote Code Execution via multiple vectors
- File upload bypass techniques
- Command injection with encoding bypasses

**Network & Service Exploitation:**
- SMB/NFS enumeration and exploitation
- Redis database access
- SSH tunneling and port forwarding
- FTP brute-forcing
- Internal service discovery

**Privilege Escalation:**
- Sudo misconfigurations (NOPASSWD, CVE exploits)
- Linux capabilities abuse
- PATH hijacking techniques
- SUID binary exploitation
- Environment variable manipulation

**Container Security:**
- Docker container detection
- Volume-based privilege escalation
- Container escape through cron jobs
- Shared volume exploitation

**Cryptography & Encoding:**
- Base64 encoding/decoding
- Steganographic analysis
- Whitespace encoding
- Hash cracking (MD5, Argon2)

## Tools & Frameworks

- **Reconnaissance:** Nmap, enum4linux, showmount
- **Web Analysis:** Burp Suite, FFUF, SQLMap
- **Exploitation:** Hydra, Metasploit, custom scripts
- **Post-Exploitation:** LinPEAS, pwncat, socat
- **Container:** Docker, Gitea
- **Misc:** ExifTool, John the Ripper, strings

## Document Structure

Each write-up follows a standardized penetration testing methodology:

1. **Executive Summary** - High-level overview and attack path
2. **Reconnaissance** - Initial enumeration and service discovery
3. **Exploitation** - Vulnerability identification and exploitation
4. **Post-Exploitation** - Lateral movement and credential discovery
5. **Privilege Escalation** - Path to root access
6. **Conclusion** - Key findings and lessons learned
7. **Remediation** - Security recommendations

## Format

All documents are provided in PDF format with:
- Professional typesetting
- Syntax-highlighted code blocks
- Detailed tool explanations
- Step-by-step methodology
- Comprehensive screenshots
- Remediation guidance

## Disclaimer

These write-ups document security research conducted in authorized, isolated lab environments. All techniques are presented for educational purposes only. Unauthorized access to computer systems is illegal.

## Author

**M3RICK**  
Epitech Toulouse - Cybersecurity Specialization

## License

This documentation is provided for educational purposes. Reproduction and distribution are permitted with attribution.

---

*"The best defense is understanding the offense."*
