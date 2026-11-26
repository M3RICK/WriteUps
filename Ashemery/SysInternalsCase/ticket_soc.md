# Case #001 - Fake SysInternals download leads to persistent service

| Field | Value |
|---|---|
| Date | 2022-11-15 |
| Severity | High |
| TLP | CLEAR |
| PAP | CLEAR |
| Status | Resolved (analysis done, remediation to do) |
| Analyst | M3RICK |
| Tags | `T1562.001` `T1565.001` `T1204.002` `T1543.003` `T1036.005` `T1070.004` |

Training case (Ashemery Challenge #7), analysed offline from a disk image.

## Description

The user downloaded what looked like the SysInternals suite. Nothing opened, and the PC got slower after that.

What happened:
- A few minutes before, someone used PowerShell on the IEUser account to turn off Defender and add `www.sysinternals.com` to the `hosts` file, pointing to 192.168.15.10.
- So when the user went to www.sysinternals.com, Edge downloaded a fake `SysInternals.exe` from 192.168.15.10.
- The user ran it. It dropped `C:\Windows\vmtoolsIO.exe` and installed it as a service that runs as SYSTEM and starts at every boot.
- The service deletes everything in `C:\Windows\Prefetch` every second. I did not see it steal data or talk to the network.

Why High: the malware runs as SYSTEM and survives reboots, and the antivirus and updates were turned off.

Host: MSEDGEWIN10, Windows 10 build 17763. User: IEUser.

## Timeline (UTC)

| Time | What |
|---|---|
| 21:17:00 | PowerShell: Defender exclusion on `C:`, real-time protection off, auto updates off |
| 21:17:03 | `hosts` file changed |
| 21:18:40 | Download of `http://www.sysinternals.com/SysInternals.exe` in Edge |
| 21:19:00 | IEUser runs `SysInternals.exe` |
| 21:19:22 | Service installed (event 7045) |
| 21:19:23 | Service starts, Prefetch files start getting deleted |
| 21:19:25 | Service switched to automatic start (event 7040) |
| 21:20:58 | `SysInternals.exe` deleted (don't know by who) |

## Observables

| Type | Value | Note |
|---|---|---|
| hash | `72e6d1728a546c2f3ee32c063ed09fa6ba8c46ac33b0dd2e354087c1ad26ef48` | SysInternals.exe, VT 53/72 |
| hash | `5b01cca415277e5fb0c454690142b9b4029a1566938875497d2f0593db555270` | vmtoolsIO.exe, VT 2/70 |
| url | `http://www.sysinternals.com/SysInternals.exe` | real domain, redirected by `hosts` |
| ip | `192.168.15.10` | serves the malware |
| domain | `www.malware430.com` | also in `hosts` |
| filename | `C:\Windows\vmtoolsIO.exe` | the service binary |
| registry | `HKLM\SYSTEM\ControlSet001\Services\VMwareIOHelperService` | the service |

## Tasks

- [x] Check the image hash
- [x] Find the downloaded file and where it came from
- [x] Prove it was executed
- [x] Find the persistence
- [x] Understand what vmtoolsIO.exe does (Ghidra)
- [ ] Isolate the PC
- [ ] Stop and delete the service (`sc stop VMwareIOHelperService`, `sc delete VMwareIOHelperService`) and delete `C:\Windows\vmtoolsIO.exe`
- [ ] Clean the `hosts` file
- [ ] Turn Defender and updates back on, run a full scan
- [ ] Block 192.168.15.10 and look for the observables on other PCs
- [ ] Find out who ran the PowerShell commands, reset the IEUser password
- [ ] Reimage the PC if possible (someone had admin rights on it)

## Notes

- Not found: `C:\Windows\Temp\Hex2Dec.zip` (VirusTotal says the dropper downloads it).
- The image was taken 13 min after the infection, so I could not see the slowdown itself.

Full write-up: https://github.com/M3RICK/WriteUps/blob/main/Ashemery/SysInternalsCase/SysInternalsCase-WriteUp.pdf
