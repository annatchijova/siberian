# Windows Level 1 lab kit

This directory contains a read-only baseline collector for controlled SIBERIAN validation. It inventories the VM and a bounded set of existing Windows evidence; it does not generate test activity, change audit policy, clear or resize logs, change a USN journal, or acquire raw evidence.

## Trust boundary and contract

- Run only in a disposable, snapshot-restorable Windows VM prepared for the study.
- Treat all collected values and native command output as untrusted observations. The script records collection errors and never turns a failed query into a zero count.
- The operator supplies a run ID, an output directory, and the UTC analysis interval. The script rejects reversed intervals and refuses to overwrite an existing report.
- The script writes one UTF-8 JSON report under the chosen output directory, reads OS/registry/volume/log/policy/USN metadata, and queries counts for events 4624, 4634, 4688, and 5156. Event queries are capped at 100,000 records each; capped values are lower bounds.
- It does not assert event completeness, artifact absence, deletion, actor, or intent. It does not collect raw Security log records.
- The report may include host name, account name, edition, build, volume labels, policy output, and event counts. Keep it local during the study and review or redact it before sharing.

## Run

Use an elevated PowerShell session so policy and Security log queries have the best chance of succeeding. A denied query remains an explicit collection error. Follow the lab host's approved script-signing policy; do not weaken machine-wide execution policy for the collector.

```powershell
& .\lab\collect_windows_baseline.ps1 `
  -RunId 'pilot-win10-22h2-a01' `
  -OutputDirectory 'C:\SIBERIAN-Lab\run-001' `
  -IntervalStartUtc '2026-10-04T12:00:00Z' `
  -IntervalEndUtc '2026-10-04T12:15:00Z'
```

The collector does not set execution policy. If local policy disallows it, follow the lab host's approved script-signing procedure.

Preserve the JSON unchanged, record its printed SHA-256 in the run log, and separately preserve VM image identity, snapshot ID, policy exports, raw log/journal acquisitions, action/intervention timeline, and parser versions. The report alone is an inventory aid, not a validation result. Mark each matrix row `lab-observed` only after a reviewer can reproduce the run from those materials.

## Current validation boundary

The script has not been executed on Windows in this repository environment. It is a collection aid, not validated collection software. The host's PowerShell version, permissions, localization, event-log state, volume APIs, and `fsutil` behavior can affect output. Record errors and inspect the raw source on every run. No current lab results are claimed.
