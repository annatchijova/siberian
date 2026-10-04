# SIBERIAN artifact catalog review

**Catalog version:** `windows-msdocs-2026-10-04-v1`

**Review status:** source and applicability review; not empirical validation.

The inherited VIGÍA seed mixed event logs, current system state, caches, file-system traces, and externally collected records as if they were comparable expectations. It also assigned ordinal “erasure difficulty” and “forensic value” weights without a calibration dataset. SIBERIAN removes those weights and activates only entries whose basic semantics and key applicability conditions can be tied to primary documentation.

## Active conditional entries

| Activity | Catalog entry | Conditions required before confirming absence | Main interpretation limit |
| --- | --- | --- | --- |
| Process creation | Windows Security event 4688 | Process Creation auditing enabled for the interval; Security log acquired and covering the interval | Event generation depends on audit policy. Command-line content has a separate policy setting. |
| Network connection | Windows Security event 5156 | Filtering Platform Connection success auditing enabled; Security log acquired and covering the interval | Success auditing can create very high event volume. |
| Successful logon | Windows Security event 4624 | Successful Logon auditing enabled; Security log acquired and covering the interval | Event is recorded on the computer where the logon session is created. |
| Session termination | Windows Security event 4634 | Successful Logoff auditing enabled; Security log acquired and covering the interval | Abrupt shutdown and other conditions can prevent a corresponding logoff event. |
| File-system change | NTFS USN change journal | Target volume is NTFS; journal active for interval; acquired journal range covers interval without wrap | Journal size/allocation bounds mean older records may no longer be retained. |

The linked Microsoft event/policy sources document Windows 10. The implementation rejects `CONFIRMED_ABSENT` for other declared releases and leaves those entries unknown with `catalog_scope_unverified`; it does not infer non-applicability. Build-specific compatibility within the Windows 10 family is not yet validated. It also requires analyst-maintained evidence references with declared time intervals for each listed condition. The program checks the references' presence and declared coverage, not whether their contents support the claim.

## Seed entries deferred or excluded

- **Prefetch, ShimCache, Amcache:** deferred until behavior is documented against supported Windows versions, configuration, and acquisition context. Amcache evidence can support file presence/existence but does not by itself prove execution; see the [Microsoft Incident Response guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf).
- **DNS cache:** excluded as a default retained artifact. It is volatile, affected by cache lifetime and flushes, and is not a durable network history.
- **MFT and LNK files:** deferred. Their survival and interpretation depend on file-system state, user activity, cleanup, volume scope, and parser/acquisition behavior. The narrower USN entry is also conditional and volume-specific.
- **Service registry state and event 7045:** deferred pending primary-source review of generation conditions, retention, and what each record can establish.
- **Netflow and packet captures:** excluded from the host catalog because they require separately configured external collection. A missing host artifact cannot establish whether those sensors collected data.
- **`Get-NetTCPConnection` output:** excluded as historical evidence; it reports current connection state rather than a durable event history.
- **Linux seed entries** (`bash_history`, syslog, process accounting, audit logs, `netstat`, iptables, pcap, inode metadata, ext4 journal, inotify): deferred. Linux is not a supported profile until distribution/version, service configuration, retention, acquisition, and source documentation are reviewed per entry.

## Primary references

- [Windows event 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688) and [Audit Process Creation policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation)
- [Windows event 5156](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156) and [Audit Filtering Platform Connection policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-filtering-platform-connection)
- [Windows event 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) and [Audit Logon policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon)
- [Windows event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634), [Audit Logoff policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logoff)
- [Windows event log retention policy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0b9673a7-ce0a-49b4-912b-591efdb37cdf)
- [NTFS USN journal operations](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)

This review establishes documented generation and applicability caveats, not real-world survival rates. No artifact absence is evidence of deliberate deletion by itself. Statistical selectivity, rival-hypothesis comparison, and calibrated decisions remain future work.
