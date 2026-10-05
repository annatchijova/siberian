"""
siberian/plaso_import.py
========================
Plaso l2tcsv import adapter — converts explicitly mapped Plaso events
to SIBERIAN PRESENT observations.

DESIGN CONTRACT (from docs/PLASO_IMPORT.md):
1. Accepts only documented, explicitly selected Plaso output format and
   bounded input file; rejects malformed CSV, unexpected headers, invalid
   encoding, oversized fields, and ambiguous mappings.
2. Requires user-authored mapping from Plaso event attributes
   (source, sourcetype, type, format) to registered SIBERIAN activity
   and artifact type. Free-text desc matching alone is NOT sufficient.
3. Converts only matched rows into PRESENT observations. Preserves source
   row identity and input file's digest as provenance; never rewrites
   or modifies the source export.
4. Keeps unmatched rows as import diagnostics, not as artifact states.
5. Makes no completeness claim from CSV row counts, export counters, or
   absent matches. Analyst provides coverage/acquisition evidence separately.
6. Produces deterministic import diagnostics and fails closed on ambiguity.

THREAT MODEL:
- Malformed, filtered, truncated, or attacker-crafted export can cause
  incorrect present claims or resource exhaustion.
- Bounds, strict parsing, explicit mapping, and provenance address risks.
- Adapter cannot establish Plaso storage file or underlying acquisition
  authenticity/completeness.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .adversarial_silence import (
    ANALYSIS_SCHEMA_VERSION,
    AdversarialSilenceAnalyzer,
    AnalysisContext,
    ArtifactStatus,
    CATALOG_VERSION,
    catalog_for_profile,
)
from .catalog import ExpectedArtifact


# ---------------------------------------------------------------------------
# Constants and limits
# ---------------------------------------------------------------------------

# Plaso l2tcsv official 17 fields (from Plaso documentation)
PLASO_L2TCSV_FIELDS = (
    "date", "time", "timezone", "MACB", "source", "sourcetype",
    "type", "user", "host", "short", "desc", "version",
    "filename", "inode", "notes", "format", "extra"
)

# Limits for resource exhaustion prevention
MAX_ROWS = 1_000_000
MAX_FIELD_SIZE = 1_000_000  # 1MB per field
MAX_FILE_SIZE = 500_000_000  # 500MB

# Supported Plaso formats (explicit, not guessed)
SUPPORTED_PLASO_FORMATS = {
    "l2tcsv": {
        "required_fields": set(PLASO_L2TCSV_FIELDS),
        "description": "Plaso l2tcsv output format",
        "doc_url": "https://github.com/log2timeline/plaso/blob/main/docs/sources/user/Output-format-l2tcsv.md",
    }
}


# ---------------------------------------------------------------------------
# Mapping definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PlasoToSiberianMapping:
    """Maps Plaso event attributes to SIBERIAN catalog activity + artifact."""
    # Match criteria (ALL must match)
    source: str
    sourcetype: Optional[str] = None
    type: Optional[str] = None
    format: Optional[str] = None

    # Target SIBERIAN catalog entry
    activity: str = ""
    artifact_type: str = ""

    def matches(self, row: Dict[str, str]) -> bool:
        if row.get("source") != self.source:
            return False
        if self.sourcetype is not None and row.get("sourcetype") != self.sourcetype:
            return False
        if self.type is not None and row.get("type") != self.type:
            return False
        if self.format is not None and row.get("format") != self.format:
            return False
        return True


@dataclass
class ImportDiagnostics:
    """Import run diagnostics (not artifact states)."""
    input_file: str
    input_hash: str
    plaso_format: str
    total_rows: int = 0
    matched_rows: int = 0
    unmatched_rows: int = 0
    rejected_rows: int = 0
    mapping_errors: int = 0
    observations_created: int = 0  # PRESENT observations only
    unknown_conditions_created: int = 0  # UNKNOWN with reason=conditions_unverified
    evidence_ref_prefix: str = ""
    mappings_used: List[str] = field(default_factory=list)
    unmatched_sample: List[Dict[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_file": self.input_file,
            "input_hash": self.input_hash,
            "plaso_format": self.plaso_format,
            "total_rows": self.total_rows,
            "matched_rows": self.matched_rows,
            "unmatched_rows": self.unmatched_rows,
            "rejected_rows": self.rejected_rows,
            "mapping_errors": self.mapping_errors,
            "observations_created": self.observations_created,
            "unknown_conditions_created": self.unknown_conditions_created,
            "evidence_ref_prefix": self.evidence_ref_prefix,
            "mappings_used": self.mappings_used,
            "unmatched_sample": self.unmatched_sample[:100],  # cap sample
            "errors": self.errors,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


# ---------------------------------------------------------------------------
# Default mappings for SIBERIAN catalog
# ---------------------------------------------------------------------------

def get_default_mappings() -> List[PlasoToSiberianMapping]:
    """Built-in mappings for SIBERIAN Windows catalog entries.
    Each mapping targets a specific catalog artifact by activity+artifact_type.
    """
    return [
        # Security Event 4688 - Process Creation
        PlasoToSiberianMapping(
            source="Microsoft-Windows-Security-Auditing",
            sourcetype="Security",
            type="4688",
            activity="process_execution",
            artifact_type="security_event_4688",
        ),
        # Security Event 5156 - Filtering Platform Connection
        PlasoToSiberianMapping(
            source="Microsoft-Windows-Security-Auditing",
            sourcetype="Security",
            type="5156",
            activity="permitted_network_connection",
            artifact_type="security_event_5156",
        ),
        # Security Event 4624 - Logon
        PlasoToSiberianMapping(
            source="Microsoft-Windows-Security-Auditing",
            sourcetype="Security",
            type="4624",
            activity="successful_logon",
            artifact_type="security_event_4624",
        ),
        # Security Event 4634 - Logoff / Session Termination
        PlasoToSiberianMapping(
            source="Microsoft-Windows-Security-Auditing",
            sourcetype="Security",
            type="4634",
            activity="session_termination",
            artifact_type="security_event_4634",
        ),
        # USN Change Journal - NTFS file changes
        PlasoToSiberianMapping(
            source="NTFS",
            sourcetype="USN",
            type="USN_CHANGE",
            format="usn",
            activity="file_change",
            artifact_type="ntfs_usn_change_journal",
        ),
    ]


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------

class PlasoImporter:
    """
    Plaso l2tcsv to SIBERIAN case file importer.

    Usage:
        importer = PlasoImporter(mappings=get_default_mappings())
        case_file, diagnostics = importer.import_file(
            plaso_csv_path,
            case_template_path="template.json",  # provides context, activities
            output_path="case_imported.json",
        )
    """

    def __init__(
        self,
        mappings: List[PlasoToSiberianMapping],
        evidence_ref_prefix: str = "case://import/plaso",
        max_rows: int = MAX_ROWS,
        max_field_size: int = MAX_FIELD_SIZE,
    ) -> None:
        self.mappings = mappings
        self.evidence_ref_prefix = evidence_ref_prefix
        self.max_rows = max_rows
        self.max_field_size = max_field_size

        # Validate mappings target valid catalog entries
        self._validate_mappings()

    def _validate_mappings(self) -> None:
        """Ensure all mappings target existing catalog entries."""
        # We validate against the Windows catalog (only supported profile)
        catalog = catalog_for_profile("windows")
        valid_pairs = {(e.action, e.artifact_type) for e in catalog}

        for m in self.mappings:
            if (m.activity, m.artifact_type) not in valid_pairs:
                raise ValueError(
                    f"Mapping targets unknown catalog entry: "
                    f"action={m.activity!r}, artifact_type={m.artifact_type!r}. "
                    f"Valid pairs: {sorted(valid_pairs)}"
                )

    def _compute_file_hash(self, path: Path) -> str:
        """SHA-256 of input file for provenance."""
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _detect_format(self, reader: csv.DictReader) -> str:
        """Detect Plaso output format from headers. Explicit, no guessing."""
        headers = set(reader.fieldnames or [])

        for fmt_name, fmt_info in SUPPORTED_PLASO_FORMATS.items():
            if fmt_info["required_fields"].issubset(headers):
                return fmt_name

        raise ValueError(
            f"Unsupported or malformed Plaso CSV. "
            f"Headers: {sorted(headers)}. "
            f"Expected one of: {list(SUPPORTED_PLASO_FORMATS.keys())}"
        )

    def _validate_row(self, row: Dict[str, str], row_num: int) -> Optional[str]:
        """Validate single row. Returns error message or None if valid."""
        # Check field count
        if len(row) != len(PLASO_L2TCSV_FIELDS):
            return f"Row {row_num}: expected {len(PLASO_L2TCSV_FIELDS)} fields, got {len(row)}"

        # Check field sizes and None values
        for field, value in row.items():
            if value is None:
                return f"Row {row_num}: field {field!r} is missing (None)"
            if len(value) > self.max_field_size:
                return f"Row {row_num}: field {field!r} exceeds {self.max_field_size} bytes"

        # Required fields non-empty for matching
        for req in ("source", "type"):
            if not row.get(req, "").strip():
                return f"Row {row_num}: required field {req!r} is empty"

        return None

    def _find_mapping(self, row: Dict[str, str]) -> Optional[PlasoToSiberianMapping]:
        """Find matching mapping for row. Returns None if no match or ambiguous."""
        matches = [m for m in self.mappings if m.matches(row)]
        if len(matches) == 1:
            return matches[0]
        elif len(matches) > 1:
            # Ambiguous mapping — fail closed
            raise ValueError(
                f"Ambiguous mapping for row: {len(matches)} mappings match. "
                f"Mappings: {[f'{m.source}/{m.sourcetype}/{m.type}/{m.format}' for m in matches]}"
            )
        return None

    def _build_evidence_ref(self, row_num: int, mapping: PlasoToSiberianMapping) -> str:
        """Build evidence reference for matched observation."""
        return f"{self.evidence_ref_prefix}/row-{row_num}/{mapping.activity}/{mapping.artifact_type}"

    def import_file(
        self,
        plaso_csv_path: str | Path,
        case_template_path: str | Path,
        output_path: str | Path,
    ) -> Tuple[Dict[str, Any], ImportDiagnostics]:
        """
        Import Plaso CSV into SIBERIAN case file.

        Args:
            plaso_csv_path: Path to Plaso l2tcsv export.
            case_template_path: Path to SIBERIAN case template (provides context, activities).
            output_path: Output path for enriched case file.

        Returns:
            Tuple of (enriched_case_dict, diagnostics).
        """
        plaso_path = Path(plaso_csv_path)
        template_path = Path(case_template_path)
        out_path = Path(output_path)

        if not plaso_path.is_file():
            raise FileNotFoundError(f"Plaso CSV not found: {plaso_path}")
        if not template_path.is_file():
            raise FileNotFoundError(f"Case template not found: {template_path}")

        # Check file size
        file_size = plaso_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            raise ValueError(f"Input file {file_size} bytes exceeds {MAX_FILE_SIZE} byte limit")

        # Compute input hash for provenance
        input_hash = self._compute_file_hash(plaso_path)

        # Load case template
        with template_path.open("r", encoding="utf-8") as f:
            case_template = json.load(f)

        # Validate template schema
        if case_template.get("schema_version") != "siberian-case-v1":
            raise ValueError(f"Template must be siberian-case-v1, got {case_template.get('schema_version')}")

        diagnostics = ImportDiagnostics(
            input_file=str(plaso_path),
            input_hash=input_hash,
            plaso_format="",
            evidence_ref_prefix=self.evidence_ref_prefix,
        )

        # Parse CSV and process rows
        with plaso_path.open("r", encoding="utf-8", newline="") as f:
            # Strict: reject extra fields, require all 17 fields
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise ValueError("CSV has no headers")

            plaso_format = self._detect_format(reader)
            diagnostics.plaso_format = plaso_format

            # Prepare enriched case (deep copy)
            enriched_case = json.loads(json.dumps(case_template))

            # Track which (activity, artifact_type) we've already created PRESENT for
            # to avoid duplicates from multiple matching rows
            present_created: Set[Tuple[str, str]] = set()

            for row_num, row in enumerate(reader, start=1):
                if row_num > self.max_rows:
                    diagnostics.errors.append(f"Row limit {self.max_rows} exceeded")
                    diagnostics.rejected_rows += 1
                    break

                diagnostics.total_rows += 1

                # Validate row
                row_error = self._validate_row(row, row_num)
                if row_error:
                    diagnostics.errors.append(row_error)
                    diagnostics.rejected_rows += 1
                    continue

                # Find matching mapping
                try:
                    mapping = self._find_mapping(row)
                except ValueError as e:
                    diagnostics.errors.append(f"Row {row_num}: {e}")
                    diagnostics.mapping_errors += 1
                    continue

                if mapping is None:
                    diagnostics.unmatched_rows += 1
                    # Keep sample of unmatched for diagnostics
                    if len(diagnostics.unmatched_sample) < 100:
                        diagnostics.unmatched_sample.append({
                            "row": row_num,
                            "source": row.get("source", ""),
                            "sourcetype": row.get("sourcetype", ""),
                            "type": row.get("type", ""),
                            "format": row.get("format", ""),
                            "desc": row.get("desc", "")[:200],
                        })
                    continue

                # Match found
                diagnostics.matched_rows += 1
                key = (mapping.activity, mapping.artifact_type)

                # Only create observation if we haven't already for this activity+artifact
                # (multiple Plaso rows can map to same catalog entry)
                if key not in present_created:
                    # Build observation entry
                    evidence_ref = self._build_evidence_ref(row_num, mapping)

                    # Per PLASO_IMPORT.md: import creates UNKNOWN with
                    # reason="conditions_unverified" only. Plaso CSV cannot establish
                    # audit policy state, log coverage, or build applicability —
                    # those require separate analyst evidence.
                    obs_entry = {
                        "artifact_type": mapping.artifact_type,
                        "status": "unknown",
                        "reason": "conditions_unverified",
                        "evidence_ref": evidence_ref,
                        "conditions": {}  # Analyst must fill applicability conditions separately
                    }

                    # Find or create activity in enriched case
                    activity_found = False
                    for activity in enriched_case.get("activities", []):
                        if activity["action"] == mapping.activity:
                            # Check if observation already exists
                            existing = False
                            for obs in activity.get("observations", []):
                                if obs.get("artifact_type") == mapping.artifact_type:
                                    existing = True
                                    break
                            if not existing:
                                activity.setdefault("observations", []).append(obs_entry)
                                present_created.add(key)
                                diagnostics.unknown_conditions_created += 1
                                if f"{mapping.activity}/{mapping.artifact_type}" not in diagnostics.mappings_used:
                                    diagnostics.mappings_used.append(f"{mapping.activity}/{mapping.artifact_type}")
                            activity_found = True
                            break

                    if not activity_found:
                        # Activity not declared in template — create it with this observation
                        enriched_case.setdefault("activities", []).append({
                            "action": mapping.activity,
                            "observations": [obs_entry]
                        })
                        present_created.add(key)
                        diagnostics.unknown_conditions_created += 1
                        if f"{mapping.activity}/{mapping.artifact_type}" not in diagnostics.mappings_used:
                            diagnostics.mappings_used.append(f"{mapping.activity}/{mapping.artifact_type}")

            diagnostics.completed_at = datetime.now(timezone.utc).isoformat()

        # Write enriched case file
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(enriched_case, f, ensure_ascii=False, indent=2)

        return enriched_case, diagnostics


# ---------------------------------------------------------------------------
# CLI convenience
# ---------------------------------------------------------------------------

def main(argv: List[str] | None = None) -> int:
    """Standalone CLI for Plaso import."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="siberian-import-plaso",
        description="Import Plaso l2tcsv as UNKNOWN (conditions_unverified) observations into SIBERIAN case file. "
                    "PRESENT requires explicit applicability conditions from analyst.",
    )
    parser.add_argument("plaso_csv", type=Path, help="Plaso l2tcsv export file")
    parser.add_argument("template", type=Path, help="SIBERIAN case template (siberian-case-v1)")
    parser.add_argument("-o", "--output", type=Path, required=True, help="Output enriched case file")
    parser.add_argument("--mappings", type=Path, help="Optional custom mappings JSON file")
    parser.add_argument("--evidence-prefix", default="case://import/plaso", help="Evidence ref prefix")
    parser.add_argument("--max-rows", type=int, default=MAX_ROWS, help="Max rows to process")
    parser.add_argument("--diagnostics", type=Path, help="Write diagnostics JSON to file")

    args = parser.parse_args(argv)

    # Load custom mappings if provided
    mappings = get_default_mappings()
    if args.mappings:
        with args.mappings.open("r", encoding="utf-8") as f:
            custom = json.load(f)
        mappings = [PlasoToSiberianMapping(**m) for m in custom]

    importer = PlasoImporter(
        mappings=mappings,
        evidence_ref_prefix=args.evidence_prefix,
        max_rows=args.max_rows,
    )

    try:
        case, diagnostics = importer.import_file(
            args.plaso_csv, args.template, args.output
        )
        print(f"Import complete: {diagnostics.unknown_conditions_created} UNKNOWN (conditions_unverified) observations created")
        print(f"  Total rows: {diagnostics.total_rows}")
        print(f"  Matched: {diagnostics.matched_rows}")
        print(f"  Unmatched: {diagnostics.unmatched_rows}")
        print(f"  Rejected: {diagnostics.rejected_rows}")
        print(f"  Output: {args.output}")

        if args.diagnostics:
            args.diagnostics.parent.mkdir(parents=True, exist_ok=True)
            with args.diagnostics.open("w", encoding="utf-8") as f:
                json.dump(diagnostics.to_dict(), f, ensure_ascii=False, indent=2)
            print(f"  Diagnostics: {args.diagnostics}")

        if diagnostics.errors:
            print(f"  Errors: {len(diagnostics.errors)} (see diagnostics)", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"Import failed: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())