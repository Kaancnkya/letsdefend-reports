# SOC176 — Successful RDP brute force against host Matthew

**Severity:** High · **Verdict:** True Positive
**Date:** 2026-07-26 · **Analyst:** Kaan Cankaya · **Source:** LetsDefend — SOC Analyst path, alert SOC176 (Event ID 234)

---

## 1. Summary

An external source (`218.92.0.56`) brute-forced RDP against host `Matthew` (172.16.17.148). The
attempts began with non-existent usernames, then moved to the valid account `Matthew`, and finally
succeeded with a correct password. The attacker established a RemoteInteractive (RDP) session and ran
host reconnaissance commands. No account creation or lateral movement was observed. The host has been
isolated.

## 2. Timeline

All times 7 March 2024.

| Time | Event |
|---|---|
| 11:44 | Many RDP connections from `218.92.0.56` to `172.16.17.148:3389`, high source ports — automated brute force |
| 11:44 | Failed logons (Event 4625): early attempts `0xC0000064` (username does not exist); then `0xC000006A` for user Matthew (valid user, wrong password) |
| 11:44 | Successful logon (Event 4624), Logon Type 10 (RemoteInteractive/RDP), user Matthew, source `218.92.0.56` |
| 11:45:18 | `cmd.exe` opened (parent `explorer.exe` — interactive desktop session) |
| 11:45:51 | `whoami` |
| 11:45:58 | `net user letsdefend` |
| 11:46:34 | `net localgroup administrators` |
| 11:46:53 | `netstat -ano` |

## 3. Analysis

**Source.** `218.92.0.56` is flagged on VirusTotal and AbuseIPDB as a known brute-force attacker,
in an APNIC (China) range. Reused scanning infrastructure, not a one-off.

**The brute force.** Log Management, filtered on the source IP, showed dozens of connections to
port 3389 in the same minute, each from a different high source port — the pattern of an automated
tool. The Windows Security failure events (4625) tell the progression through their error codes:

- `0xC0000064` — username does not exist. These are the "non-existing accounts" in the alert's
  trigger reason; the attacker was guessing account names blindly.
- `0xC000006A` — username correct, password wrong. At this point the attacker had found a valid
  account (`Matthew`) and was guessing its password.

**The compromise.** A successful logon (Event 4624) with **Logon Type 10 (RemoteInteractive)** for
`Matthew` from the same source IP confirms the brute force succeeded and the session was RDP. This is
the pivot of the case: the attack moved from attempt to confirmed access.

**Post-exploitation.** Immediately after the logon, an interactive `cmd.exe` (parent `explorer.exe`,
consistent with an RDP desktop session) ran a sequence of reconnaissance commands: `whoami` to
confirm the current user, `net user letsdefend` to query an account, `net localgroup administrators`
to list local admins, and `netstat -ano` to view active connections and listening ports. This is
standard host discovery.

`net user letsdefend` was a query, not an account creation (creation requires `/add`), so no new
account was added. Review of the host's later network activity showed no outbound connection to
another internal host, so no lateral movement was observed within the visible window.

## 4. Indicators of Compromise

| Indicator | Type | Verdict | Source |
|---|---|---|---|
| `218.92.0.56` | IPv4 | Malicious | VirusTotal, AbuseIPDB, logs |
| `172.16.17.148` (Matthew) | Host | Compromised | Event 4624 |
| `Matthew` | Account | Compromised | Event 4624, Logon Type 10 |
| `3389/RDP` | Service | Exposed | Firewall log — entry vector |

Machine-readable copy: [`iocs.csv`](./iocs.csv)

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Credential Access | T1110 — Brute Force | Repeated 4625 failures from one source over RDP |
| Initial Access | T1133 — External Remote Services | RDP exposed externally; entry over 3389 |
| Discovery | T1033 — System Owner/User Discovery | `whoami` |
| Discovery | T1087.001 — Account Discovery: Local Account | `net user letsdefend` |
| Discovery | T1069.001 — Permission Groups Discovery: Local Groups | `net localgroup administrators` |
| Discovery | T1049 — System Network Connections Discovery | `netstat -ano` |

## 6. Verdict and Reasoning

True positive, and the attack succeeded. Evidence is layered across independent sources: firewall and
OS logs show the brute-force volume, 4625 error codes show the progression from invalid usernames to
a valid account, a 4624 with Logon Type 10 confirms a successful RDP logon, and the process/terminal
history shows attacker reconnaissance in the same session.

**Scope:** one host compromised. No account creation and no lateral movement observed. Because a
successful interactive session occurred, the host must be treated as fully compromised regardless of
what was seen afterward.

**Action taken:** host isolated.

**Recommended follow-up:** force a password reset for `Matthew` and any account reachable from this
host; review for persistence (scheduled tasks, services, new accounts, run keys) created after 11:44;
reimage the host given a confirmed interactive compromise.

## 7. Recommendations

1. **Take RDP off the public internet.** Port 3389 should not be directly reachable. Place RDP behind
   a VPN or a gateway; this removes the entire attack surface used here.
2. **Enforce an account lockout policy.** Locking an account after a small number of failed attempts
   defeats password brute forcing directly — the attacker here made dozens of attempts without any
   lockout.
3. **Require Network Level Authentication and MFA for remote access.** NLA forces authentication
   before a session is established; MFA means a guessed password alone is not enough.
4. **Enforce strong password policy.** The account was compromised by guessing, which implies a weak
   or common password.

ISO/IEC 27001:2022: A.5.15 (access control), A.8.5 (secure authentication), A.8.2 (privileged access
rights), A.8.20 (network security), A.5.24–A.5.26 (incident management).

## 8. What I Learned

- On a 4625, the error code is the story: `0xC0000064` (no such user), `0xC000006A` (valid user,
  wrong password), `0xC0000234` (locked). Tracking them shows the attacker narrowing in.
- A 4624 with Logon Type 10 is the proof of a successful RDP logon. Logon Type is the field that
  distinguishes RDP (10) from console (2) or network (3).
- `net user <name>` without `/add` is a query, not an account creation. Reading the exact command
  matters before claiming what the attacker did.
- A successful interactive logon means the host is compromised, even if no further action is visible.
  The verdict follows the confirmed access, not the amount of post-access activity that happened to
  be captured.

---

*Analysis performed in the LetsDefend training environment. No production or customer data is involved.*
