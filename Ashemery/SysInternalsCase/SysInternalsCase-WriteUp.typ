#import "../../Sherlock/template.typ": *

#show: report.with(
  title: "SysInternalsCase",
  subtitle: "Ashemery DFIR case",
  meta: (
    ("Category", "DFIR, Windows 10 disk forensics, malware analysis"),
    ("Evidence", [`SysInternalsCase.E01`, logical image of one NTFS partition (40 GiB)]),
    ("Question", "What happened, and when?"),
    ("Tools", [The Sleuth Kit, `ewfverify`, regipy, `esedbexport`, `evtx_dump`, Eric Zimmerman's MFTECmd and LECmd, Ghidra]),
    ("Method", [SANS FOR500 poster, step by step with an AI tutor (Claude)]),
    ("Author", "M3RICK"),
  ),
  tldr: [
    *Found:* a fake SysInternals download, served from the real domain through a modified `hosts` file, installed a service that deletes every Prefetch file once per second.\
    *Proved:* the full chain from 21:17:03 to 21:20:58 UTC, with the key steps backed by two or more independent artifacts.\
    *Explained:* the slowdown, by reverse engineering the service in Ghidra and watching the same behavior in the USN journal.
  ],
)

= Summary

The user of a Windows 10 virtual machine (`MSEDGEWIN10`, account `IEUser`) visited `www.sysinternals.com` in Microsoft Edge and downloaded `SysInternals.exe`. About ninety seconds earlier, the same account had used PowerShell to exclude `C:` from Windows Defender, turn off real-time protection, disable automatic updates and add two lines to the `hosts` file. Those lines sent `www.sysinternals.com` to `192.168.15.10`, a host on the local network. The browser reached the real domain name and received a malicious file over plain HTTP.

`SysInternals.exe` is a downloader. When the user double-clicked it, no window appeared. In 36 seconds it fetched `C:\Windows\vmtoolsIO.exe`, installed it as an automatic service running as SYSTEM under a fake VMware name, and exited. The service has one job: it deletes the content of `C:\Windows\Prefetch` every second. That removes the traces of its own execution, and it takes away the Prefetch data Windows uses to start programs faster. It is the most likely mechanism behind the slowdown the user reported.

The disk was acquired about 13 minutes after the infection, so it shows the mechanism of the slowdown but not its growth over days.


= Evidence Handling

The evidence is an EWF container produced by FTK Imager 4.5.0.3. The hash stored in the acquisition log was recomputed before any analysis:

```
$ ewfverify -d sha1 SysInternalsCase.E01
MD5 hash calculated over data:  389ac32f7334160cf230bab6dc42d037
SHA1:                           efe08e6806e34828255ad7ce45f57688594267e9
```

Both values match the FTK log, so the data has not changed since acquisition. The image was then exposed read-only with `ewfmount` and read with The Sleuth Kit, without mounting the file system:

```
$ ewfmount SysInternalsCase.E01 /mnt/ewf/       # /mnt/ewf/ewf1, raw stream, read-only
$ mmls /mnt/ewf/ewf1                            # no output: logical image, partition only
$ fsstat /mnt/ewf/ewf1                          # NTFS, serial BAB00A24B009E7A9
$ fls -r -p /mnt/ewf/ewf1 > fls_complet.txt     # full file list, searched with grep afterwards
```

`mmls` prints nothing because FTK copied the partition starting at sector 2048, not the disk. The file system starts at offset 0, so no offset is needed. In `fsstat`, `Version: Windows XP` is the NTFS format version (3.1), and the volume label is free text: neither one identifies the operating system.

All registry hives were extracted with their transaction logs and replayed before analysis (see Method and Mistakes). Every timestamp in this report is UTC.

= System Context

#block(breakable: false)[
#table(
  columns: (auto, 1fr, auto),
  [Item], [Value], [Source],
  [OS], [Windows 10 Enterprise Evaluation, build 17763 (1809)], [`SOFTWARE\Microsoft\Windows NT\CurrentVersion`],
  [Computer name], [`MSEDGEWIN10`], [`SYSTEM\ControlSet001\Control\ComputerName`],
  [Time zone], [Pacific Standard Time, `ActiveTimeBias` = 480 (UTC-8)], [`SYSTEM\ControlSet001\Control\TimeZoneInformation`],
  [User], [`IEUser`, RID 1000, 16 logons, last logon 21:18:17], [SAM (`samparse`), `ProfileList`],
)]


Three independent clues (the `IEUser` account, the `MSEDGEWIN10` name and the Evaluation edition) identify one of Microsoft's free test virtual machines. The `sshd` account is not suspicious: its key dates from 2019-03-19, the day Microsoft built the image, three years before the incident.

The time zone also explains the FTK log. It writes `13:32:05` with no zone; read as PST, the acquisition started at 21:32:05 UTC, 13 minutes after the payload appeared on disk.

#note("Offline registry")[`CurrentControlSet` does not exist in a hive file. Windows creates it at boot as an alias of `ControlSet00N`, where N is the value of `SYSTEM\Select\Current`. Here `Current = 1`, so every path uses `ControlSet001`.]

= Timeline

#block(breakable: false)[
#table(
  columns: (auto, 1fr, auto),
  [Time (UTC)], [Event], [Source],
  [21:16:27], [PowerShell runs], [Prefetch (MFT)],
  [21:16:43], [`IEUser` opens `Documents\notes.txt` (benign)], [MFT, LNK, Jump List],
  [21:17:00], [PowerShell: Defender excludes `C:`, real-time protection off], [PSReadLine history, SOFTWARE],
  [21:17:01], [`NoAutoUpdate = 1`], [SOFTWARE (replayed)],
  [*21:17:03*], [*`hosts` modified: two domains to `192.168.15.10`*], [MFT, PSReadLine history],
  [21:18:17], [Last logon of `IEUser`], [SAM],
  [21:18:40], [Edge requests `http://www.sysinternals.com/SysInternals.exe`], [WebCache, USN],
  [21:18:51], [`SysInternals.exe` written to `C:\Users\Public\Downloads`], [MFT, USN],
  [*21:19:00*], [*`IEUser` double-clicks `SysInternals.exe`*], [UserAssist, MFT],
  [21:19:17], [`C:\Windows\vmtoolsIO.exe` written], [MFT],
  [21:19:22], [Service installed (event 7045), `vmtoolsIO.exe` starts], [System.evtx, Prefetch (MFT)],
  [21:19:23], [Service writes "in OnStart"; first Prefetch files deleted (192 within the second)], [Application.evtx, USN],
  [21:19:25], [Service switched to automatic start (event 7040)], [System.evtx, SYSTEM],
  [21:19:36], [`SysInternals.exe` exits (probable)], [BAM],
  [21:20:58], [`SysInternals.exe` deleted, not through the Recycle Bin], [USN],
  [21:32:05], [Disk acquisition starts], [FTK log (13:32:05 PST)],
)]


= Analysis

== Finding the Downloaded File

The user's `Downloads` folder only contained `desktop.ini`. A search of the full file list for the name the user gave returned three entries, two of them deleted (`*`):

```
$ grep -i sysinternals fls_complet.txt
# EDGE = Users/IEUser/AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe
r/r   124558: EDGE/AC/#!001/MicrosoftEdge/Cache/WMFWC1O7/SysInternals[1].exe
-/r * 124561: EDGE/TempState/Downloads/SysInternals.exe.51m0nh7.partial
-/r * 124567: Users/Public/Downloads/SysInternals.exe
```

The file was saved in the shared `C:\Users\Public\Downloads`, not in the user's folder. It was later deleted, but Edge kept a copy in its cache. That copy was extracted with `icat`, renamed with a `.bin` extension so nothing on the analysis host would run it, and hashed. Only the hash was searched on VirusTotal; uploading the file would make the sample public.

```
$ icat /mnt/ewf/ewf1 124558 > malware/SysInternals.exe.bin
$ sha256sum malware/SysInternals.exe.bin
72e6d1728a546c2f3ee32c063ed09fa6ba8c46ac33b0dd2e354087c1ad26ef48
```

VirusTotal returned 53/72 with generic labels (`trojan.jaik/deyma`). Its automatic code summary described a downloader that hides its console, drops `c:\Windows\vmtoolsIO.exe`, installs a service named `VMwareIOHelperService` and fetches `c:\Windows\Temp\Hex2Dec.zip`. *These claims were treated as leads and checked one by one on the disk.* The first two were confirmed; no trace of `Hex2Dec.zip` was found.

== Download Source

Edge Legacy stores its cache and history in `WebCacheV01.dat`, an ESE database. `esedbexport` turns each table into a text file. The `Containers` table maps container IDs to their role; container 20 is the cache folder where the copy was found:

```
$ esedbexport -t export WebCacheV01.dat
$ grep -i sysinternals export.export/Container_20.39 | awk -F'\t' '{print $18, $19, $11}'
http://www.sysinternals.com/SysInternals.exe  SysInternals[1].exe  Nov 15, 2022 21:18:40.808
```

`sysinternals.com` belongs to Microsoft and redirects to its documentation; it does not serve a single executable, and the URL uses plain HTTP. The `hosts` file explains it:

```
$ icat /mnt/ewf/ewf1 42564 | grep -v '^#'
192.168.15.10    www.malware430.com
192.168.15.10    www.sysinternals.com
```

Windows reads `hosts` before asking a DNS server. With these lines, the right name led to the attacker's host, and without TLS no certificate error could warn the user. The file was last modified at 21:17:03, before the download and before the last logon.

== Who Changed the hosts File

A filesystem timeline (`fls -m` and `mactime`) around 21:17 is mostly noise: 1,818 events in three minutes. After removing access-only entries and noisy folders, a PowerShell Prefetch at 21:16:27 led to the PSReadLine history of `IEUser`:

```
$ icat /mnt/ewf/ewf1 27754 | cat -n     # ConsoleHost_history.txt
1  Add-MpPreference -ExclusionPath 'C:'
2  Set-MpPreference -DisableRealtimeMonitoring $true
3  New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name WindowsUpdate -Force
4  New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name AU -Force
5  New-ItemProperty -Path HKLM:\...\WindowsUpdate\AU -Name NoAutoUpdate -PropertyType DWord `
     -Value 1 -Force
6  Add-Content -Path $env:windir\System32\drivers\etc\hosts `
     -Value "`n192.168.15.10`twww.malware430.com" -Force
7  Add-Content -Path $env:windir\System32\drivers\etc\hosts `
     -Value "`n192.168.15.10`twww.sysinternals.com" -Force
```

The history file was created at 21:17:00 and last written at 21:17:03.567879, the exact modification time of `hosts`. A text file can be edited, so the effects were checked in the registry: the Defender exclusion `C:` exists under `SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`, and `NoAutoUpdate = 1` was written at 21:17:01. This also explains why a file detected by 53 engines was able to run: Defender was off.

These commands were entered interactively, in three seconds, with no other malware on the system. In this lab it is most likely the case author preparing the scenario. In a real case, the finding would read: an operator with administrator rights disabled the defenses and hijacked name resolution before the infection.

== Execution of SysInternals.exe

No Prefetch file exists for `SysInternals.exe`. Three other artifacts prove it ran:

#table(
  columns: (auto, auto, 1fr),
  [Artifact], [Time], [What it shows],
  [UserAssist (`NTUSER.DAT` of `IEUser`)], [21:19:00.261], [Launched from Explorer, run count 1, focus time 47 ms],
  [Amcache (replayed)], [21:19:01], [SHA-1 `fa1002b0...3dcf`, publisher "sysinternals, inc.", product "sysinternals suite downloader"],
  [BAM (`SYSTEM`, SID `...-1000`)], [21:19:36], [Last execution, about 36 s after launch],
)

The MFT `Accessed` time of the file (21:19:00.245) is 16 ms from the UserAssist entry. The 47 ms of focus match "the tools did not open": the program hid its window. The SHA-1 recorded by Amcache matches the cache copy, so the sample sent to VirusTotal is the file that ran.

== Persistence

The service exists in the replayed `SYSTEM` hive:

```
$ regipy-dump hives/SYSTEM_clean -p '\ControlSet001\Services\VMwareIOHelperService'
timestamp 2022-11-15T21:19:25.359258  ImagePath c:\Windows\vmtoolsIO.exe  Start 2
DisplayName VMWare IO Helper Service   ObjectName NT AUTHORITY\SYSTEM   WOW64 332
```

`System.evtx` records the same action from another angle. Event 7045 (record 975, 21:19:22.026653) reports the installation of "VMWare IO Helper Service" with `c:\Windows\vmtoolsIO.exe`, demand start, running as `NT AUTHORITY\SYSTEM`. Three seconds later, event 7040 (record 976, 21:19:25.359258) switches it from demand start to automatic start.


The 7040 event and the registry key share the same timestamp to the microsecond. Both events carry the SID of `IEUser`, because the downloader running in that session created the service. Two details make the 7045 stand out among the legitimate ones on the same day, even without knowing the name: the legitimate ones that day come from `S-1-5-18` and point into `Program Files` or the drivers folder, while this one comes from a user SID and points to the root of `C:\Windows`. No event 4697 exists in `Security.evtx`, whose content covers the period: service installation auditing was not enabled.

== What vmtoolsIO.exe Does

The payload scores 2/70 on VirusTotal, with no summary. `strings` shows forged version information (`CompanyName: VMware, Inc.`, `ProductName: VMware Input & Output Helper Service`) and the class names `CSampleService` and `CServiceBase`, which come from Microsoft's C++ Windows service sample. These strings show what the binary can do; the code shows what it does. In Ghidra, `OnStart` (`FUN_00401480`) logs a message and queues a worker; the worker (`FUN_00401700`) is the whole payload:

```c
// FUN_00401700, simplified
while (!stopping) {
    now = time();
    if (now - last > 0xE10) {             // 3600 s; last = 0 at start, so this runs at once
        delete_in_prefetch(L"*.pf");  last = now;
    }
    delete_in_prefetch(L"*.*");           // every iteration
    Sleep(1000);
}
// FUN_00401560: FindFirstFileW("C:\\Windows\\Prefetch\\" + pattern), DeleteFileW, FindNextFileW
```

*The code was then checked against the disk.* The "in OnStart" message written by `ReportEventW` is in `Application.evtx` at 21:19:23.517, once, with no matching "in OnStop". The USN journal holds 0 Prefetch deletions before that time and 214 after, starting at 21:19:23.517 with 87 files in the same timestamp and 192 within that second. Later entries show the loop running: `SVCHOST.EXE-F737CE0B.pf` was created at 21:20:59.157 and deleted 0.3 s later.

This explains three observations from earlier in the case. The Prefetch of `SysInternals.exe` never reached the disk (the USN journal has no trace of it): Windows writes Prefetch files in batches, and the service started emptying the folder 23 seconds after the launch. The Prefetch entry of `vmtoolsIO.exe` has an initialized size of 0: it was deleted before Windows wrote its content to disk. And the slowdown: Prefetch lets Windows preload what a program needs at start; with the folder emptied every second, every launch is a cold start and Windows rebuilds files that are deleted at once. The real effect is modest, but it is the only cause consistent with all the evidence.

== Other Artifacts

- *SRUM.* `vmtoolsIO.exe` ran as `S-1-5-18` (SYSTEM), which confirms the service account. `SysInternals.exe` received 600,880 bytes; the payload weighs 289,280, so about 311 KB more was downloaded, which fits the `Hex2Dec.zip` claim without proving it. SRUM last flushed at 21:21:10, so it covers only two minutes of the infection.
- *Deletion of the downloader.* The USN journal shows `SysInternals.exe` deleted at 21:20:58. The downloader had exited and the payload only touches `C:\Windows\Prefetch`, so a third actor deleted it, without the Recycle Bin. Explorer Jump Lists were accessed in the same second, a hint of a manual deletion from Explorer, not a proof.
- *USB.* The replayed `SYSTEM` hive has no `USB` or `USBSTOR` branch under `Enum`: no USB device was ever enumerated.

#pagebreak()
= How This Investigation Was Done

This was my first disk investigation. I did it with an AI tutor (Claude, Anthropic) set up to teach rather than to solve: one concept and one step at a time, with a question after each step that I had to answer before moving on. The tutor explained each tool and prepared many of the commands; I ran them on the image, read the outputs and proposed the interpretations. When my reasoning was wrong, it usually pointed to the contradiction and let me find the fix; when I was stuck, it explained the concept.

*The plan followed the SANS "Windows Forensic Analysis" poster* (FOR500, by Kathryn Hedley, SANS Institute, available at #link("https://www.sans.org/posters/windows-forensic-analysis")[sans.org/posters/windows-forensic-analysis]), category by category: System Information, Account Usage, Browser Activity, Application Execution, File and Folder Opening, Deleted Items and File Knowledge, Network Activity, External Device / USB. Persistence (services and event logs) and the reverse engineering of the payload were added because the case needed them.

I reverse engineered the payload in Ghidra myself: `OnStart`, the worker loop and the Prefetch deletion function. The AI had run an automated decompilation beforehand, only to know where to guide me.

To be precise about what the AI did directly:
- it wrote the short Python decoder for the SRUM `SruDbIdMapTable` and ran the Prefetch deletion count on the USN journal (0 before, 214 after the service start);
- it pointed me to some artifacts while I was lost in the filesystem timeline (the PowerShell history, `notes.txt`).

The report was drafted with AI assistance from the investigation journal; I directed the changes and reviewed every claim against the evidence.

The mistakes below include two made by the AI tutor, marked as such: catching them was part of the work.

= Method and Mistakes

The conclusions above are the result; this section is how I got there, including the wrong turns, because each one changed how I work.

#note("Absence of evidence")[The missing Prefetch for `SysInternals.exe` first led me to conclude that it never ran. It contradicted another fact: `vmtoolsIO.exe`, dropped by `SysInternals.exe`, was on disk and had run. UserAssist, BAM and Amcache then proved the execution, and the reverse engineering showed why the Prefetch was gone. Since then I write "not found", never "did not happen".]

#note("Dirty hives")[Windows writes registry changes to `.LOG1`/`.LOG2` files before it flushes them into the hive. With the incident 13 minutes before acquisition, recent changes were still in the logs: 273 dirty pages in `SYSTEM`, 634 in `SOFTWARE`. `NoAutoUpdate` only exists in the replayed `SOFTWARE`. Every hive is now extracted with its logs, the log sizes are checked (an empty `LOG2` breaks the replay), and the logs are replayed into a copy before any query.]

#note("Filters that hide results")[Several empty outputs were caused by the query, not the data. A `tail -3` suggested by the AI tutor once hid the service in the original hive. A `grep` on the service key name missed event 7045, which uses the display name with spaces; searching by event ID found it. `regipy-dump` prints nothing and returns 0 for a key that does not exist. Before concluding that something is absent, I now check that the command could have shown it.]

#note("Capability is not action")[I read `DeleteService` in `strings` as evidence removal, and `SecurityChange`/`StreamChange` in the USN journal as masquerading. Both were wrong: the first is the standard `-remove` option of any service, the second is the ACL and the Mark of the Web written for every download. In the same way, an access-only (`.a..`) timeline entry on `powershell.exe` was Explorer reading icons for the Start menu, not an execution.]

#note("Tested hypotheses")[Two hypotheses were proved wrong by a direct test. "The Prefetch cluster was overwritten by another file" was contradicted by `ifind`, which showed no other owner; the file was never written. "35 Amcache entries means the hive is dirty", proposed by the AI tutor, was contradicted by the same count after replay. Both are kept in the notes with the test that disproved them.]

#note("Analysis copies have their own dates")[LECmd reported a 2026 creation date for a LNK file: the date of my extracted copy. Original timestamps come from the MFT of the image, never from a copy on the analysis host.]

= Limitations

- The image covers about 13 minutes of infection with no reboot. The growing slowdown described by the user is explained by the mechanism, not measured.
- The actor who deleted `SysInternals.exe` at 21:20:58 is not identified; the USN journal does not record the process.
- `Hex2Dec.zip` was not found. SRUM traffic suggests a second download.
- The intent behind the PowerShell preparation is an interpretation. The facts are the commands, their author account and their effects.

= Indicators of Compromise

#table(
  columns: (auto, 1fr),
  [Type], [Value],
  [SHA-256, `SysInternals.exe`], [`72e6d1728a546c2f3ee32c063ed09fa6ba8c46ac33b0dd2e354087c1ad26ef48`],
  [SHA-1, `SysInternals.exe`], [`fa1002b02fc5551e075ec44bb4ff9cc13d563dcf`],
  [SHA-256, `vmtoolsIO.exe`], [`5b01cca415277e5fb0c454690142b9b4029a1566938875497d2f0593db555270`],
  [URL], [`http://www.sysinternals.com/SysInternals.exe` (with hijacked resolution)],
  [IP], [`192.168.15.10`],
  [Domain], [`www.malware430.com`],
  [Service], [`VMwareIOHelperService`, "VMWare IO Helper Service"],
  [Files], [`C:\Windows\vmtoolsIO.exe`, `C:\Users\Public\Downloads\SysInternals.exe`],
  [Configuration], [`hosts` entries to `192.168.15.10`, Defender exclusion `C:`, `NoAutoUpdate = 1`],
)

= MITRE ATT&CK Mapping

#table(
  columns: (auto, 1fr, 1fr),
  [ID], [Technique], [Evidence],
  [T1562.001], [Impair Defenses: Disable or Modify Tools], [Defender exclusion and real-time protection off],
  [T1562], [Impair Defenses], [Automatic updates disabled],
  [T1565.001], [Data Manipulation: Stored Data Manipulation (closest match)], [`hosts` entries redirecting a trusted domain],
  [T1204.002], [User Execution: Malicious File], [Double-click on `SysInternals.exe` (UserAssist)],
  [T1105], [Ingress Tool Transfer], [`vmtoolsIO.exe` downloaded by the dropper],
  [T1036.005], [Masquerading: Match Legitimate Name or Location], [SysInternals and VMware names, forged PE metadata],
  [T1543.003], [Create or Modify System Process: Windows Service], [`VMwareIOHelperService`, automatic, SYSTEM],
  [T1070.004], [Indicator Removal: File Deletion], [Prefetch wiped every second],
)

= Tools

`ewfverify` and `ewfmount` (libewf) for integrity and read-only access; The Sleuth Kit (`mmls`, `fsstat`, `fls`, `icat`, `istat`, `blkcat`, `ifind`, `ffind`, `mactime`) for the file system; regipy for hive queries, plugins and transaction log replay; `esedbexport` (libesedb) for the WebCache and SRUM databases; `evtx_dump` for event logs; Eric Zimmerman's MFTECmd and LECmd, run with .NET on Linux, for the USN journal and LNK files; Ghidra for static reverse engineering; VirusTotal for hash reputation only, with no upload.

#v(1em)
#text(size: 8.5pt, fill: muted)[Every finding comes from an investigation journal that records each command, its output and its interpretation. The case is an educational dataset; all analysis was done offline on the image, and no sample was executed.]
