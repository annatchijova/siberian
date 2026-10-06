# SIBERIAN artifact catalog review

**Catalog version:** `windows-msdocs-2026-10-04-v3`

**Review status:** source and applicability review; not empirical validation.

The supported range in the current implementation is broader than the evidence currently represented by its generic `Windows 10` label. A required build attestation is supplied by the caller; the library does not check it against a per-build/per-edition matrix. Windows 10 Home/Pro reached end of support on October 14, 2025; LTSC editions have separate lifecycles. See Microsoft's [Windows 10 lifecycle table](https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro). The source-by-source limits and per-entry lab status are in the [active catalog matrix](CATALOG_MATRIX.md); validation design is in the [Level 1 validation protocol](LEVEL1_VALIDATION_PROTOCOL.md).

The inherited VIGÍA seed mixed event logs, current system state, caches, file-system traces, and externally collected records as if they were comparable expectations. It also assigned ordinal “erasure difficulty” and “forensic value” weights without a calibration dataset. SIBERIAN removes those weights and activates only entries whose basic semantics and key applicability conditions can be tied to primary documentation.

## Active conditional entries

| Activity | Catalog entry | Conditions required before confirming absence | Main interpretation limit |
| --- | --- | --- | --- |
| Process creation | Windows Security event 4688 | Timestamped process-execution evidence; host build applicability attested; Process Creation success auditing enabled; Security log acquired and covering the interval | Event generation depends on audit policy. Command-line content has a separate policy setting. |
| Permitted network connection | Windows Security event 5156 | Timestamped evidence of a WFP-permitted connection; host build applicability attested; Filtering Platform Connection success auditing enabled; Security log acquired and covering the interval | Event 5156 does not represent every network connection; success auditing is conditional and high-volume. |
| Successful logon | Windows Security event 4624 | Timestamped evidence of a successful logon on the destination host; host build applicability attested; Logon success auditing enabled; Security log acquired and covering the interval | Event is recorded on the computer where the logon session is created. |
| Session termination | Windows Security event 4634 | Timestamped evidence of a session termination; host build applicability attested; Audit Logoff success enabled; Security log acquired and covering the interval | Event 4634 records session termination, not necessarily user-initiated logoff. |
| File-system change | NTFS USN change journal | Timestamped evidence of the file change; host build applicability attested; target volume is NTFS; journal active; acquired journal range covers interval without wrap | Journal size/allocation bounds mean older records may no longer be retained. |

The linked Microsoft event/policy sources document Windows 10. The implementation rejects `CONFIRMED_ABSENT` for other declared releases and leaves those entries unknown with `catalog_scope_unverified`; it does not infer non-applicability. A confirmed absence requires timestamped evidence for the primary action, a separate reference to the acquired source/query, a build-applicability attestation, and analyst-maintained evidence references with declared validity intervals for every listed condition. Build-specific compatibility within the Windows 10 family is not checked against a maintained matrix. The program checks references' presence, the action timestamp's interval, and declared condition coverage, not whether reference contents support the claims.

## Seed entries deferred or excluded

- **Prefetch, ShimCache, Amcache:** deferred until behavior is documented against supported Windows versions, configuration, and acquisition context. Amcache evidence can support file presence/existence but does not by itself prove execution; see the [Microsoft Incident Response guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf).
- **DNS cache:** excluded as a default retained artifact. It is volatile, affected by cache lifetime and flushes, and is not a durable network history.
- **MFT:** now included as `ntfs_mft_entry` (catalog v4). It was previously listed here as deferred while the catalog already contained it — the two documents contradicted each other, which is what `tests/test_catalog_version_binding.py` now prevents. The entry is conditional on an NTFS volume and a whole-volume acquisition, and states that a missing record proves nothing because records are reused. Its parser is **unvalidated against a real `$MFT`**; see `docs/red-team/NIVEL6_MFT_AUDIT.md`.
- **LNK files:** still deferred. Survival and interpretation depend on file-system state, user activity, cleanup, and parser behavior.
- **Source reachability (checked 2026-10-05):** 10 of 12 unique catalog URLs returned HTTP 200. Both `ntfs_mft_entry` refs were unreachable — a fabricated `ms-fat` Open Specifications GUID and a non-existent `libyal/libfsntfs` `MFT.md` path. Replaced with three verified Microsoft sources. This check is manual and dated rather than a unit test on purpose: a test that depends on the network is a flaky test, and a flaky test trains people to ignore it.
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
