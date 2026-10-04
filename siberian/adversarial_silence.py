"""Descriptive analysis of expected artifacts that are confirmed absent.

Adapted from VIGÍA's ``vigia/patterns/adversarial_silence.py``. The original
catalogue and weights are retained as research assumptions, not validated
probabilities. This module does not infer deletion, attribution, or intent.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from fractions import Fraction
from typing import Mapping


@dataclass(frozen=True)
class ExpectedArtifact:
    """An artifact expected for an action under a declared OS profile.

    The fractions are ordinal research weights from the VIGÍA seed catalogue;
    they are not empirically calibrated probabilities.
    """

    artifact_type: str
    erasure_difficulty: Fraction
    forensic_value: Fraction
    detection_command: str

    def __post_init__(self) -> None:
        if not isinstance(self.artifact_type, str) or not self.artifact_type:
            raise ValueError("artifact_type must not be empty")
        if not isinstance(self.detection_command, str):
            raise TypeError("detection_command must be str")
        for name, value in (
            ("erasure_difficulty", self.erasure_difficulty),
            ("forensic_value", self.forensic_value),
        ):
            if not isinstance(value, Fraction):
                raise TypeError(f"{name} must be fractions.Fraction")
            if not Fraction(0) <= value <= Fraction(1):
                raise ValueError(f"{name} must be between 0 and 1")


class ArtifactStatus(str, Enum):
    PRESENT = "present"
    CONFIRMED_ABSENT = "confirmed_absent"
    UNKNOWN = "unknown"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass(frozen=True)
class Observation:
    status: ArtifactStatus
    explanation: str | None = None


@dataclass(frozen=True)
class SilenceRecord:
    action: str
    expected_artifact: ExpectedArtifact
    observation: Observation


@dataclass(frozen=True)
class SilenceAnalysisResult:
    """Exact descriptive metrics and a digest of the complete analysis input.

    ``selectivity_score`` is ``None`` unless both difficult and easy artifact
    groups have at least one in-scope, known observation.
    """

    silence_score: Fraction | None
    selectivity_score: Fraction | None
    erasure_sophistication: Fraction | None
    expected_count: int
    known_count: int
    confirmed_absent_count: int
    unknown_count: int
    out_of_scope_count: int
    audit_hash: str
    records: tuple[SilenceRecord, ...]
    top_investigation_hints: tuple[str, ...]


_WINDOWS_ARTIFACTS: dict[str, tuple[ExpectedArtifact, ...]] = {
    "process_execution": (
        ExpectedArtifact("prefetch_entry", Fraction(8, 10), Fraction(9, 10),
                         r"dir C:\Windows\Prefetch\*.pf"),
        ExpectedArtifact("shimcache_entry", Fraction(7, 10), Fraction(8, 10),
                         r"reg query HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"),
        ExpectedArtifact("amcache_entry", Fraction(6, 10), Fraction(8, 10),
                         r"C:\Windows\AppCompat\Programs\Amcache.hve"),
        ExpectedArtifact("event_4688", Fraction(3, 10), Fraction(7, 10),
                         "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688}"),
    ),
    "network_connection": (
        ExpectedArtifact("dns_cache_entry", Fraction(2, 10), Fraction(6, 10),
                         "ipconfig /displaydns"),
        ExpectedArtifact("firewall_log", Fraction(4, 10), Fraction(7, 10),
                         "Get-WinEvent -FilterHashtable @{LogName='Security';Id=5156}"),
        ExpectedArtifact("netflow_record", Fraction(5, 10), Fraction(8, 10),
                         "Get-NetTCPConnection"),
    ),
    "file_creation": (
        ExpectedArtifact("mft_entry", Fraction(9, 10), Fraction(9, 10),
                         "MFTECmd.exe -f '$MFT'"),
        ExpectedArtifact("usnjrnl_entry", Fraction(8, 10), Fraction(8, 10),
                         "MFTECmd.exe -f '$UsnJrnl:$J'"),
        ExpectedArtifact("lnk_file", Fraction(3, 10), Fraction(5, 10),
                         r"dir %APPDATA%\Microsoft\Windows\Recent\*.lnk"),
    ),
    "service_installation": (
        ExpectedArtifact("event_7045", Fraction(4, 10), Fraction(9, 10),
                         "Get-WinEvent -FilterHashtable @{LogName='System';Id=7045}"),
        ExpectedArtifact("registry_service", Fraction(6, 10), Fraction(8, 10),
                         r"reg query HKLM\SYSTEM\CurrentControlSet\Services"),
        ExpectedArtifact("prefetch_entry", Fraction(8, 10), Fraction(7, 10),
                         r"dir C:\Windows\Prefetch\*.pf"),
    ),
    "user_login": (
        ExpectedArtifact("event_4624", Fraction(3, 10), Fraction(8, 10),
                         "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624}"),
        ExpectedArtifact("event_4634", Fraction(3, 10), Fraction(7, 10),
                         "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4634}"),
        ExpectedArtifact("ntuser_dat", Fraction(7, 10), Fraction(6, 10),
                         r"dir C:\Users\*\NTUSER.DAT /A:H"),
    ),
}

_LINUX_ARTIFACTS: dict[str, tuple[ExpectedArtifact, ...]] = {
    "process_execution": (
        ExpectedArtifact("bash_history", Fraction(2, 10), Fraction(6, 10),
                         "cat ~/.bash_history"),
        ExpectedArtifact("syslog_entry", Fraction(4, 10), Fraction(7, 10),
                         "grep <pid> /var/log/syslog"),
        ExpectedArtifact("proc_accounting", Fraction(5, 10), Fraction(7, 10),
                         "lastcomm"),
        ExpectedArtifact("audit_log", Fraction(5, 10), Fraction(9, 10),
                         "ausearch -sc execve"),
    ),
    "network_connection": (
        ExpectedArtifact("netstat_entry", Fraction(1, 10), Fraction(5, 10),
                         "netstat -antp"),
        ExpectedArtifact("iptables_log", Fraction(4, 10), Fraction(7, 10),
                         "grep DROP /var/log/syslog"),
        ExpectedArtifact("pcap_fragment", Fraction(6, 10), Fraction(9, 10),
                         "tcpdump -r capture.pcap"),
    ),
    "file_creation": (
        ExpectedArtifact("inode_entry", Fraction(8, 10), Fraction(8, 10),
                         "stat <file>"),
        ExpectedArtifact("ext4_journal", Fraction(9, 10), Fraction(9, 10),
                         "debugfs -R 'logdump' /dev/sda1"),
        ExpectedArtifact("fam_inotify_log", Fraction(3, 10), Fraction(5, 10),
                         "inotifywait -m /path"),
    ),
}

_PROFILES: Mapping[str, Mapping[str, tuple[ExpectedArtifact, ...]]] = {
    "windows": _WINDOWS_ARTIFACTS,
    "linux": _LINUX_ARTIFACTS,
}


class AdversarialSilenceDetector:
    """Compare known artifact observations against the seed expectation table.

    Metrics describe the supplied observations only. This class has no verdict
    thresholds and does not equate a missing artifact with deliberate erasure.
    """

    def __init__(self, os_profile: str = "windows") -> None:
        if not isinstance(os_profile, str):
            raise TypeError("os_profile must be str")
        profile = os_profile.strip().lower()
        if profile not in _PROFILES:
            raise ValueError(f"unsupported OS profile: {os_profile!r}")
        self._os_profile = profile
        self._kb = _PROFILES[profile]
        self._actions: set[str] = set()
        self._observations: dict[tuple[str, str], Observation] = {}

    def register_primary_action(self, action: str) -> None:
        """Register an action whose expected secondary artifacts are analyzed."""
        if not isinstance(action, str):
            raise TypeError("action must be str")
        if action not in self._kb:
            raise ValueError(
                f"unknown action {action!r} for {self._os_profile}; "
                f"known actions: {', '.join(sorted(self._kb))}"
            )
        self._actions.add(action)

    def register_observation(
        self,
        action: str,
        artifact_type: str,
        status: ArtifactStatus | str,
        explanation: str | None = None,
    ) -> None:
        """Record one explicit observation for an expected artifact.

        Repeating the same observation is idempotent. Conflicting observations
        for the same action/artifact pair raise ``ValueError``.
        """
        if not isinstance(action, str) or not isinstance(artifact_type, str):
            raise TypeError("action and artifact_type must be str")
        if explanation is not None and not isinstance(explanation, str):
            raise TypeError("explanation must be str or None")
        if action not in self._actions:
            raise ValueError(f"register action {action!r} before its observations")
        expected_types = {item.artifact_type for item in self._kb[action]}
        if artifact_type not in expected_types:
            raise ValueError(
                f"artifact {artifact_type!r} is not expected for action {action!r}"
            )
        try:
            parsed_status = ArtifactStatus(status)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid artifact status: {status!r}") from exc
        observation = Observation(parsed_status, explanation)
        key = (action, artifact_type)
        previous = self._observations.get(key)
        if previous is not None and previous != observation:
            raise ValueError(f"conflicting observations for {action}/{artifact_type}")
        self._observations[key] = observation

    def analyze(self) -> SilenceAnalysisResult:
        """Compute exact, descriptive metrics over in-scope known observations."""
        records = tuple(
            SilenceRecord(
                action=action,
                expected_artifact=artifact,
                observation=self._observations.get(
                    (action, artifact.artifact_type), Observation(ArtifactStatus.UNKNOWN)
                ),
            )
            for action in sorted(self._actions)
            for artifact in sorted(self._kb[action], key=lambda item: item.artifact_type)
        )
        scored = [
            record for record in records
            if record.observation.status in {
                ArtifactStatus.PRESENT, ArtifactStatus.CONFIRMED_ABSENT
            }
        ]
        denominator = sum(
            (record.expected_artifact.forensic_value for record in scored), Fraction(0)
        )
        absent = [
            record for record in scored
            if record.observation.status is ArtifactStatus.CONFIRMED_ABSENT
        ]
        silence_score = (
            sum((r.expected_artifact.forensic_value for r in absent), Fraction(0)) / denominator
            if denominator else None
        )

        hard = [r for r in scored if r.expected_artifact.erasure_difficulty > Fraction(1, 2)]
        easy = [r for r in scored if r.expected_artifact.erasure_difficulty <= Fraction(1, 2)]
        hard_absent = sum(
            r.observation.status is ArtifactStatus.CONFIRMED_ABSENT for r in hard
        )
        easy_absent = sum(
            r.observation.status is ArtifactStatus.CONFIRMED_ABSENT for r in easy
        )
        selectivity_score = None
        if hard and easy:
            hard_rate = Fraction(hard_absent, len(hard))
            easy_rate = Fraction(easy_absent, len(easy))
            selectivity_score = max(hard_rate - easy_rate, Fraction(0))

        erasure_sophistication = (
            sum((r.expected_artifact.erasure_difficulty for r in absent), Fraction(0))
            / len(absent)
            if absent else None
        )
        hints = _build_hints(absent, self._os_profile)
        audit_hash = _compute_analysis_hash(self._os_profile, records)
        status_counts = {
            status: sum(record.observation.status is status for record in records)
            for status in ArtifactStatus
        }
        return SilenceAnalysisResult(
            silence_score=silence_score,
            selectivity_score=selectivity_score,
            erasure_sophistication=erasure_sophistication,
            expected_count=len(records),
            known_count=len(scored),
            confirmed_absent_count=len(absent),
            unknown_count=status_counts[ArtifactStatus.UNKNOWN],
            out_of_scope_count=status_counts[ArtifactStatus.OUT_OF_SCOPE],
            audit_hash=audit_hash,
            records=records,
            top_investigation_hints=hints,
        )


def _build_hints(
    absent_records: list[SilenceRecord], os_profile: str
) -> tuple[str, ...]:
    sorted_records = sorted(
        absent_records,
        key=lambda record: (
            -record.expected_artifact.forensic_value,
            record.action,
            record.expected_artifact.artifact_type,
        ),
    )
    return tuple(
        f"[{os_profile.upper()}] CONFIRMED_ABSENT: {record.expected_artifact.artifact_type} "
        f"(research forensic_value={_percent(record.expected_artifact.forensic_value)}%, "
        f"research erasure_difficulty={_percent(record.expected_artifact.erasure_difficulty)}%). "
        f"Suggested check: {record.expected_artifact.detection_command}"
        for record in sorted_records[:5]
    )


def _percent(value: Fraction) -> int:
    return value.numerator * 100 // value.denominator


def _compute_analysis_hash(
    os_profile: str, records: tuple[SilenceRecord, ...]
) -> str:
    payload = {
        "schema": "siberian-adversarial-silence-v1",
        "os_profile": os_profile,
        "records": [
            {
                "action": record.action,
                "artifact_type": record.expected_artifact.artifact_type,
                "erasure_difficulty": str(record.expected_artifact.erasure_difficulty),
                "forensic_value": str(record.expected_artifact.forensic_value),
                "detection_command": record.expected_artifact.detection_command,
                "status": record.observation.status.value,
                "explanation": record.observation.explanation,
            }
            for record in records
        ],
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
