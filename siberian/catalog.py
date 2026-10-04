"""Versioned, source-linked artifact expectations used by SIBERIAN v1.

An entry is a conditional expectation. It is not enabled for absence analysis
unless the caller supplies a reference for every required condition.
"""
from __future__ import annotations

from dataclasses import dataclass


CATALOG_VERSION = "windows-msdocs-2026-10-04-v2"


@dataclass(frozen=True)
class ExpectedArtifact:
    action: str
    artifact_type: str
    description: str
    scope: str
    required_conditions: tuple[str, ...]
    retention: str
    interpretation_limit: str
    source_refs: tuple[tuple[str, str], ...]
    documented_os_release_prefix: str = "Windows 10"

    def __post_init__(self) -> None:
        for field_name in (
            "action", "artifact_type", "description", "scope", "retention",
            "interpretation_limit",
            "documented_os_release_prefix",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{field_name} must be a non-empty string")
        if not isinstance(self.source_refs, tuple) or not self.source_refs or any(
            not isinstance(ref, tuple)
            or len(ref) != 2
            or not isinstance(ref[0], str)
            or not ref[0]
            or not isinstance(ref[1], str)
            or not ref[1].startswith("https://")
            for ref in self.source_refs
        ):
            raise ValueError("source_refs must contain titled HTTPS references")
        if (
            not isinstance(self.required_conditions, tuple)
            or not self.required_conditions
            or any(not isinstance(item, str) or not item for item in self.required_conditions)
            or len(set(self.required_conditions)) != len(self.required_conditions)
        ):
            raise ValueError("required_conditions must be non-empty and unique")

    def supports_os_release(self, os_release: str) -> bool:
        """Return whether this entry's sources document the declared release family."""
        release = os_release.casefold()
        prefix = self.documented_os_release_prefix.casefold()
        return release == prefix or release.startswith(prefix + " ")


WINDOWS_CATALOG: tuple[ExpectedArtifact, ...] = (
    ExpectedArtifact(
        action="process_execution",
        artifact_type="security_event_4688",
        description="Security event 4688 records a process creation event.",
        scope="Windows 10, matching the linked event and policy documentation; confirm event schema locally.",
        required_conditions=(
            "host_build_matches_documented_catalog_scope",
            "audit_process_creation_enabled_for_interval",
            "security_log_acquired_and_covers_interval",
        ),
        retention="Security log retention/overwrite policy and acquisition coverage must include the interval.",
        interpretation_limit="A missing 4688 is not meaningful if process-creation auditing was disabled or the log interval is incomplete.",
        source_refs=(
            ("4688 event semantics", "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688"),
            ("Audit Process Creation policy", "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation"),
            ("Event log retention policy", "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0b9673a7-ce0a-49b4-912b-591efdb37cdf"),
        ),
    ),
    ExpectedArtifact(
        action="network_connection",
        artifact_type="security_event_5156",
        description="Security event 5156 records a connection permitted by Windows Filtering Platform.",
        scope="Windows 10 using Windows Filtering Platform, matching the linked event and policy documentation.",
        required_conditions=(
            "host_build_matches_documented_catalog_scope",
            "audit_filtering_platform_connection_success_enabled_for_interval",
            "security_log_acquired_and_covers_interval",
        ),
        retention="Security log retention/overwrite policy and acquisition coverage must include the interval.",
        interpretation_limit="Success auditing may produce very high event volume; absence is uninterpretable without the policy state and log coverage.",
        source_refs=(
            ("5156 event semantics", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156"),
            ("Audit Filtering Platform Connection policy", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-filtering-platform-connection"),
            ("Event log retention policy", "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0b9673a7-ce0a-49b4-912b-591efdb37cdf"),
        ),
    ),
    ExpectedArtifact(
        action="successful_logon",
        artifact_type="security_event_4624",
        description="Security event 4624 records a successfully created logon session.",
        scope="Windows 10, matching the linked event and policy documentation; recorded on the computer where the session is created.",
        required_conditions=(
            "host_build_matches_documented_catalog_scope",
            "audit_logon_success_enabled_for_interval",
            "security_log_acquired_and_covers_interval",
        ),
        retention="Security log retention/overwrite policy and acquisition coverage must include the interval.",
        interpretation_limit="A missing event does not show that no logon occurred unless successful logon auditing and log coverage are established.",
        source_refs=(
            ("4624 event semantics", "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624"),
            ("Audit Logon policy", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon"),
            ("Event log retention policy", "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0b9673a7-ce0a-49b4-912b-591efdb37cdf"),
        ),
    ),
    ExpectedArtifact(
        action="logoff",
        artifact_type="security_event_4634",
        description="Security event 4634 records termination of a logon session.",
        scope="Windows 10, matching the linked event and policy documentation; session termination is distinct from user-initiated logoff.",
        required_conditions=(
            "host_build_matches_documented_catalog_scope",
            "audit_logoff_success_enabled_for_interval",
            "security_log_acquired_and_covers_interval",
        ),
        retention="Security log retention/overwrite policy and acquisition coverage must include the interval.",
        interpretation_limit="A missing event does not show that a session remained active unless successful logoff auditing and log coverage are established.",
        source_refs=(
            ("4634 event semantics", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634"),
            ("Audit Logoff policy", "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logoff"),
            ("Event log retention policy", "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0b9673a7-ce0a-49b4-912b-591efdb37cdf"),
        ),
    ),
    ExpectedArtifact(
        action="file_change",
        artifact_type="ntfs_usn_change_journal",
        description="The NTFS USN change journal records file, directory, and other NTFS-object changes.",
        scope="Windows 10 NTFS volume and change interval; it is not host-wide or cross-filesystem.",
        required_conditions=(
            "host_build_matches_documented_catalog_scope",
            "target_volume_is_ntfs",
            "usn_journal_active_for_interval",
            "acquired_journal_range_covers_interval_without_wrap",
        ),
        retention="The journal has configured size/allocation bounds; confirm the queried USN range still includes the interval.",
        interpretation_limit="A missing USN record is interpretable only for a journal known to be active and acquired across the relevant range.",
        source_refs=(
            ("USN journal operations and behavior", "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn"),
        ),
    ),
)


def catalog_for_profile(os_profile: str) -> tuple[ExpectedArtifact, ...]:
    """Return a supported, versioned catalog or fail instead of guessing."""
    if not isinstance(os_profile, str):
        raise TypeError("os_profile must be str")
    if os_profile.strip().lower() != "windows":
        raise ValueError(
            f"unsupported OS profile: {os_profile!r}; available profile: 'windows'"
        )
    return WINDOWS_CATALOG
