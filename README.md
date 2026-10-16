# Attack-Defend: An Endpoint Detection Lab

## Overview
This project is a self-built security lab demonstrating a full attack-and-detect lifecycle against a Windows 11 endpoint. I built an isolated virtual network, performed a realistic endpoint intrusion from an attacker machine, and then investigated the attack from the defender's side using Windows Sysmon logging. The goal was to understand how attacker actions translate into log evidence, and to assess how much of the MITRE ATT&CK technique spectrum a standard logging configuration actually detects.

This is a lab environment I built for learning — not a real incident — but the investigation and analysis are done with the same rigor a SOC analyst would apply to a genuine one.

## Lab Architecture
- **Attacker:** Kali Linux VM (`10.0.0.1`)
- **Victim:** Windows 11 VM (`10.0.0.2`), instrumented with Sysmon
- **Network:** Isolated VirtualBox internal network (`intnet`), fully air-gapped from the internet and host — chosen so the attack generates clean, uncontaminated log evidence and cannot reach anything real.

## Tooling
- **Attack:** Metasploit Framework (msfvenom, Meterpreter), nmap
- **Detection:** Sysmon with the SwiftOnSecurity configuration, Windows Event Viewer
- **Adversary emulation:** Atomic Red Team (MITRE ATT&CK-mapped technique tests)
- **Endpoint AV:** Microsoft Defender (tested in both disabled and updated states)

## What This Project Demonstrates
1. Building and isolating a virtual lab network from scratch
2. Instrumenting an endpoint for security monitoring (Sysmon)
3. Executing a realistic reverse-shell intrusion and post-exploitation chain
4. Testing payload behavior against antivirus (and the effect of signature currency)
5. Reconstructing the attack from log evidence
6. Mapping observed activity to MITRE ATT&CK
7. Assessing detection coverage and identifying gaps

---

## Executive Summary

A simulated attacker gained remote control of a Windows 11 workstation by delivering a malicious executable disguised as a software update. Once run, the file opened a hidden connection back to the attacker, giving them an interactive foothold on the machine. From there, the attacker surveyed the system, ran commands, and installed a startup entry so their access would survive a reboot — a realistic sequence mirroring how modern endpoint intrusions unfold.

Every stage of the attack was captured by the endpoint's Sysmon logging, allowing the full intrusion to be reconstructed after the fact from log evidence alone. A second test showed that an up-to-date Microsoft Defender detected and quarantined the same payload immediately, while an offline endpoint with outdated definitions did not — illustrating how patch and definition currency directly affects endpoint security.

Finally, a structured detection-coverage assessment using Atomic Red Team mapped a sample of attacker techniques against the logging configuration, confirming strong coverage of execution and persistence activity but identifying a gap in file-deletion (anti-forensic) visibility.

---

## Attack Timeline

The following reconstructs the intrusion in chronological order, as derived from Sysmon log evidence on the victim host (`VICTIM-PC`, `10.0.0.2`).

| # | Time | Event | Evidence Source |
|---|------|-------|-----------------|
| 1 | `[t0]` | Attacker performs network reconnaissance against the victim (nmap scan). Host firewall causes all ports to appear filtered. | Attacker-side (nmap) |
| 2 | `[t1]` | Malicious payload (`update.exe`) downloaded to the victim from the attacker's web server. | Delivery / host artifact |
| 3 | `[t2]` | `update.exe` executed by the user; process launches and initiates outbound connection. | Sysmon Event ID 1 (Process Create) |
| 4 | `[t3]` | Payload establishes reverse connection to attacker at `10.0.0.1:4444` (Meterpreter session opened). | Sysmon Event ID 3 (Network Connection) |
| 5 | `[t4]` | `update.exe` spawns `cmd.exe` — anomalous parent-child relationship indicating remote command execution. | Sysmon Event ID 1, ParentImage = `update.exe` |
| 6 | `[t5]` | Attacker runs discovery commands: `whoami`, `ipconfig`, `systeminfo`. | Sysmon Event ID 1 (multiple) |
| 7 | `[t6]` | Attacker establishes persistence via a registry Run key (`HKCU\...\Run\WindowsUpdate`) pointing to the payload. | Sysmon Event ID 13 (Registry Value Set) |

### Key Observations
- The intrusion required **user execution** of the payload — consistent with phishing/social-engineering delivery, the dominant real-world initial-access vector for endpoints.
- The attacker's actions span four MITRE ATT&CK tactics: **Initial Access → Execution → Discovery → Persistence**.
- The single most telling indicator was the **parent-child anomaly** (step 5): a file in the Downloads folder spawning a command shell is highly abnormal and, on its own, is sufficient to warrant investigation.

---

## Technical Analysis

Each stage below is documented with the attacker action, the corresponding log evidence, and its MITRE ATT&CK classification.

### 4.1 Initial Access & Execution — `update.exe`

**Action:** The payload, a 64-bit Windows executable generated with `msfvenom` (`windows/x64/meterpreter/reverse_tcp`), was delivered to the victim and executed by the user under the guise of a software update.

**Evidence — Sysmon Event ID 1 (Process Create):**
- `Image: C:\Users\analyst\Downloads\update.exe`
- `User: VICTIM-PC\analyst`
- Process launched from the user's Downloads folder — an uncommon execution location for legitimate software.

**ATT&CK:** T1204 (User Execution), T1566 (Phishing — simulated delivery vector)

**Analyst note:** Execution from `\Downloads\` combined with an unsigned binary is a baseline anomaly. On its own it is low-confidence, but it becomes significant in combination with the network and process-spawn activity that immediately followed.

### 4.2 Command & Control — Reverse Connection

**Action:** Upon execution, the payload initiated an outbound TCP connection to the attacker at `10.0.0.1:4444`, establishing a Meterpreter command-and-control channel. The reverse (outbound) direction was deliberate — it evades inbound firewall rules, which block unsolicited incoming connections but permit outbound traffic.

**Evidence — Sysmon Event ID 3 (Network Connection):**
- `Image: ...\update.exe` initiating the connection
- `DestinationIp: 10.0.0.1`, `DestinationPort: 4444`

**ATT&CK:** T1571 (Non-Standard Port) / Command and Control tactic

**Analyst note:** Port 4444 is the Metasploit default and is itself a well-known indicator of compromise. A process executing from Downloads *and* immediately beaconing outbound to a raw IP on 4444 is a high-confidence detection.

### 4.3 Remote Command Execution — Process Spawn

**Action:** The attacker used the C2 session to spawn an interactive command shell on the victim.

**Evidence — Sysmon Event ID 1 (Process Create):**
- `Image: C:\Windows\System32\cmd.exe`
- `ParentImage: C:\Users\analyst\Downloads\update.exe`

**ATT&CK:** T1059.003 (Command and Scripting Interpreter: Windows Command Shell)

**Analyst note:** This parent-child relationship is the strongest single indicator in the entire intrusion. Legitimate software does not normally have a Downloads-folder executable as the parent of `cmd.exe`. This one event effectively confirms compromise.

### 4.4 Discovery

**Action:** With shell access established, the attacker ran a sequence of built-in Windows commands to understand the compromised host and its context.

**Evidence — Sysmon Event ID 1 (Process Create), multiple:**
- `whoami.exe` — current user and privilege context
- `ipconfig.exe` — network configuration
- `systeminfo.exe` — OS version, patch level, hardware

**ATT&CK:** T1033 (System Owner/User Discovery), T1016 (System Network Configuration Discovery), T1082 (System Information Discovery)

**Analyst note:** Individually, these are common administrative commands and generate false positives. Their significance is **behavioral**: three discovery commands executed in rapid succession, as children of an attacker-controlled shell, form a recognizable "host fingerprinting" pattern. This illustrates a core detection principle — context and sequence matter more than any single command.

### 4.5 Persistence — Registry Run Key

**Action:** The attacker established persistence by adding a registry Run key entry pointing to the payload, disguised with the legitimate-sounding name "WindowsUpdate." This causes the payload to re-execute automatically at every user login, surviving reboots.

**Evidence — Sysmon Event ID 13 (Registry Value Set):**
- `TargetObject: HKCU\...\CurrentVersion\Run\WindowsUpdate`
- `Details: C:\Users\analyst\Downloads\update.exe`
- `Image: C:\Windows\System32\reg.exe`

**ATT&CK:** T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)

**Analyst note:** This is a high-value detection event. The Run key is a small, well-defined, and heavily-monitored location, and the SwiftOnSecurity Sysmon configuration explicitly tags writes to it. The disguised value name ("WindowsUpdate") pointing to a Downloads-folder executable is the tell — a legitimate update mechanism would never be configured this way. The contrast between the deceptive name and the illegitimate file path is exactly what distinguishes this from benign Run key entries.

---

## Antivirus Analysis: The Effect of Definition Currency

To test the payload against endpoint antivirus, the same `update.exe` was run under two different Microsoft Defender states.

### Test 1 — Defender with outdated definitions
With Defender's real-time protection enabled but running on **outdated signature definitions** (the lab endpoint had been offline and could not receive updates), the payload executed successfully and established its C2 session without interference.

### Test 2 — Defender with current definitions
Defender's definitions were then updated to current via an offline definition package (`mpam-fe.exe`), transferred into the air-gapped lab. The identical payload was run again and was **immediately detected and quarantined on execution.**

**Detection evidence (Defender Protection History):**
- **Threat:** `Trojan:Win32/Zusy.NCD!MTB`
- **Severity:** Severe
- **Status:** Quarantined
- **Detection method:** The `!MTB` suffix indicates detection by Defender's machine-learning / behavioral engine, not a static signature alone.
- **File:** `C:\Users\analyst\Downloads\update.exe`

### Finding
The only variable changed between the two tests was signature currency. This is **not an AV bypass** — the payload is an unmodified Metasploit executable with a long-known signature, and a current Defender detects it trivially. The first test succeeded solely because the endpoint's definitions were stale.

**Implication:** Endpoints that cannot receive timely definition updates — air-gapped systems, neglected servers, or anything with broken update mechanisms — run meaningfully degraded protection. Definition and patch currency is not a background maintenance task; it is a direct determinant of whether known threats are caught. A real bypass of a current, updated Defender would require genuine evasion techniques (payload obfuscation, custom loaders), which are out of scope for this project.

---

## Detection Coverage Assessment

To move beyond a single scripted attack and systematically measure detection coverage, a sample of MITRE ATT&CK techniques was executed using **Atomic Red Team** (an open-source adversary-emulation framework). Each technique was run against the instrumented endpoint, and the Sysmon logs were then checked to determine whether the activity was captured.

Defender's real-time protection was disabled for this phase to isolate the measurement to a single question: *does the Sysmon logging configuration capture the technique?* (Defender's detection behavior was assessed separately above.)

### Coverage Matrix

| Technique | ATT&CK ID | Atomic Test | Detected? | Evidence / Notes |
|-----------|-----------|-------------|:---------:|------------------|
| Registry Run Key Persistence | T1547.001 | T1547.001-1 | ✅ Yes | Sysmon Event ID 13; event auto-tagged with ATT&CK rule name by the config |
| System Owner/User Discovery | T1033 | T1033-7 | ✅ Yes | Sysmon Event ID 1 (`whoami.exe`); no ATT&CK rule tag applied |
| Credential Access via LOLBin | T1003 | T1003-6 | ✅ Yes | Sysmon Event ID 1 (`rundll32.exe keymgr,KRShowKeyMgr`); legitimate binary, suspicious usage |
| File Deletion (Anti-Forensics) | T1070.004 | T1070.004-6 | ❌ **No** | **No Sysmon Event ID 23 generated.** FileDelete logging is disabled by default in the SwiftOnSecurity config to reduce noise. |

### Analysis
- **3 of 4 techniques were detected.** Execution and persistence activity — the stages most central to catching an intrusion — were reliably captured.
- **The undetected technique (file deletion) represents a real and understood gap.** The SwiftOnSecurity configuration deliberately omits most FileDelete (Event ID 23) logging because deletions are extremely high-volume and would flood the log with noise. This is a defensible engineering tradeoff, but it means an attacker performing anti-forensic cleanup (deleting their tools to cover tracks) would operate without generating evidence.
- **Detection quality varied even among the successes.** The persistence event was automatically tagged with its ATT&CK technique by the config, while the discovery event was captured but untagged. This highlights that "detected" is not binary — enrichment and labeling materially affect how quickly an analyst can triage an event.

### Recommendation
Enable targeted FileDelete logging (Sysmon Event ID 23) scoped to sensitive directories (e.g., system folders, common malware staging paths) rather than globally. This recovers anti-forensic visibility while keeping log volume manageable. For broader coverage, layer an EDR solution that monitors file operations behaviorally.

---

## Conclusion & Lessons Learned

This project followed a complete endpoint attack-and-detect lifecycle: building an isolated lab, instrumenting it for monitoring, executing a realistic intrusion, and then investigating that intrusion entirely from log evidence. Several lessons emerged that generalize beyond the lab:

**1. Context beats signatures.** The most reliable indicators of compromise were not individual malicious events but *relationships and sequences* — a Downloads-folder executable spawning a shell, discovery commands firing in rapid succession, a Run key pointing somewhere it shouldn't. Modern detection is fundamentally about behavior and context, not matching known-bad artifacts.

**2. Logging configuration is a set of tradeoffs, not a switch.** The same Sysmon config that gave excellent persistence and execution visibility deliberately sacrificed file-deletion visibility to control noise. Every detection gain has a cost in log volume, and understanding those tradeoffs is central to detection engineering.

**3. Maintenance currency is a security control.** The identical payload was caught or missed based solely on whether Defender's definitions were current. Patch and definition management is not background upkeep — it directly determines whether known threats are stopped.

**4. The defender's view is reconstructable.** Every attacker action, if the right telemetry is in place, leaves a trace. The core analyst skill demonstrated here is working backward from scattered log events to a coherent narrative of what happened.

### Possible Extensions
- Re-run the intrusion against a fully-updated Defender and document the evasion techniques required to succeed.
- Forward Sysmon logs to a SIEM (e.g., a local ELK or Wazuh stack) and author detection rules for each technique in the coverage matrix.
- Expand the Atomic Red Team assessment to a broader set of techniques and produce a fuller coverage heatmap.

---

*Lab environment built for educational purposes. All activity was performed against systems I own on an isolated network.*
