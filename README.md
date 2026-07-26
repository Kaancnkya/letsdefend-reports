# LetsDefend Incident Reports

Blue-team case work by Kaan Cankaya: alert triage, log and endpoint analysis, and written incident
reports produced while working through the LetsDefend SOC Analyst path.

Each case follows the same method. A hypothesis is written before enrichment, every investigative
step is recorded with its reason, indicators are mapped to MITRE ATT&CK, and the verdict is stated
with the evidence that supports it.

<!-- metrics:start -->
**3** alerts triaged · **3** incident reports published
<!-- metrics:end -->

## Case index

<!-- cases:start -->
| Date | Case | Topic | Verdict |
|---|---|---|---|
| 2026-07-26 | [`SOC338`](./cases/2026-07-26_SOC338-lumma-stealer-clickfix-phishing/report.md) | lumma stealer clickfix phishing | True Positive |
| 2026-07-26 | [`SOC176`](./cases/2026-07-26_SOC176-rdp-brute-force/report.md) | rdp brute force | True Positive |
| 2026-07-25 | [`SOC153`](./cases/2026-07-25_SOC153-suspicious-powershell-script-executed/report.md) | suspicious powershell script executed | True Positive |
<!-- cases:end -->

## Repository layout

```
templates/incident-report.md   report template used for every case
cases/YYYY-MM-DD_ID-topic/     one folder per case: report.md, iocs.csv, screenshots/
scripts/new-case.sh            scaffold a new case folder
scripts/update-metrics.sh      regenerate the metrics line and case index
```

## Background

Studying Cyber Security at Torrens University, working toward a GRC and identity governance role.
Certifications: Microsoft SC-900 (passed), ISO/IEC 27001 Lead Implementer in progress. Where a case
suggests a control improvement, the report links it to ISO/IEC 27001:2022 Annex A.

## Note on sources

All analysis is performed in the [LetsDefend](https://letsdefend.io/) training environment. No
production, customer or employer data appears in this repository.

In line with the platform's terms of use, no LetsDefend interface content is reproduced here. Reports
are written in my own words with my own tables, and cases are referenced by ID only. Screenshots,
where present, are limited to third-party tooling output such as VirusTotal or URLScan.
