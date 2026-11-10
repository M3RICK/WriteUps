# Write-Ups

Security write-ups: forensic investigations, a vulnerability analysis with detection rules, and CTF machines. Each one starts from the evidence and explains how every conclusion was reached.

All documents are PDFs written in [Typst](https://typst.app). Sources are in the repository next to each PDF when available.

## Vulnerability analysis and detection

| Write-up | Subject | Content |
|----------|---------|---------|
| [PHP2Shell](CVE/PHP2Shell/PHP2Shell-WriteUp.pdf) | CVE-2026-109618 and CVE-2026-109619, two memory corruption bugs in the PHP engine (unauthenticated RCE) | Root cause analysis from the vendor advisories and public research, attack surface, observable artifacts, and detection rules. Blue team perspective, no exploit code. |

Detection rules written for this analysis, in [`CVE/PHP2Shell/detection/`](CVE/PHP2Shell/detection):

- `php_spawns_shell.yml`: Sigma rule, PHP process spawning a shell or a download utility
- `php_worker_crash_burst.yml`: Sigma rule with correlation, burst of PHP worker segfaults or memory exhaustion
- `php2shell_upload_progress.rules`: Suricata hunting rule, multipart POST carrying `PHP_SESSION_UPLOAD_PROGRESS`

## DFIR investigations (HTB Sherlocks)

| Write-up | Evidence | Content |
|----------|----------|---------|
| [Unit42](Sherlock/Unit42/Unit42-WriteUp.pdf) | Windows Sysmon logs (EVTX) | Workstation infected by a backdoored UltraVNC dropper. EVTX to JSON with `evtx_dump` and `jq`, malicious process identification (path, parent, double extension), Dropbox delivery confirmed by DNS and Mark of the Web, time stomping (event ID 2), two-stage MSI installation, timeline and MITRE ATT&CK mapping. |
| [Brutus](Sherlock/Brutus/Brutus-WriteUp.pdf) | Linux `auth.log` and `wtmp` | Server compromised through SSH brute-force. Separating noise from signal, proving automation through volume and concurrency, PID pivoting, `auth.log` and `wtmp` correlation, backdoor account and persistence, timeline and MITRE ATT&CK mapping. |

## CTF machines (Epitech security modules)

Boot-to-root machines solved during the Epitech security modules: reconnaissance, initial access, privilege escalation, remediation.

### Third year (Chisel module)

| Write-up | Attack path |
|----------|-------------|
| [The Many Faced God](Tek3-Chisel/The-ManyFaced-God-WriteUp.pdf) | SMB and NFS enumeration, Redis access, rsync file retrieval, SSH key manipulation, TeamCity privilege escalation through PATH hijacking |
| [Patience](Tek3-Chisel/Patience-WriteUp.pdf) | Cookie-based SQL injection with WAF bypass (hex encoding), web shell, SSH tunnel to an internal Gitea, 2FA bypass through the database, Docker volume privilege escalation |
| [TekPedago](Tek3-Chisel/TekPedago-WriteUp.pdf) | LFI through PHP filter wrappers, Apache log poisoning to RCE, sudo `env` escalation, container escape through a cron job |
| [Trickster](Tek3-Chisel/Trickster-WriteUp.pdf) | SMB password cracking, command injection with Base64 bypass, Socat port forwarding to an internal service, PATH hijacking on a sudo binary |
| [Musa Troglodytarum](Tek3-Chisel/MusaTroglodytarum-WriteUp.pdf) | Hidden directory discovery, steganography, FTP brute-force, whitespace encoding, sudo CVE-2019-14287 |
| [The Binding of Cyber](Tek3-Chisel/TheBindingOfCyber-WriteUp.pdf) | Port probing across 900+ ports, NFS share, archive cracking, SSH key authentication, Linux capability abuse through `tar` |
| [Fun with Functional](Tek3-Chisel/FunWithFunctional-WriteUp.pdf) | Upload restriction bypass with a Haskell reverse shell, SSH key extraction, sudo Flask escalation through `FLASK_APP` |

Slides presenting the module: [Presentation-Chisel-Module.pdf](Tek3-Chisel/Presentation-Chisel-Module.pdf)

### Second year (Hydra module)

| Write-up | Attack path |
|----------|-------------|
| [Toss a Coin](Tek2-Hydra/TossACoin-WriteUp.pdf) (in French) | Directory fuzzing, cleartext credentials, sudo script abuse, PATH hijacking found with `strace`, sudo `perl` to root |

## Disclaimer

Everything here was done in authorized lab environments (HTB, Epitech modules) or from public sources. The CVE analysis contains no exploit code.

## Author

**M3RICK**, Epitech Toulouse
