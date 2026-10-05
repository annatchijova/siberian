"""Tests for Plaso l2tcsv import adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from siberian.plaso_import import PlasoImporter, get_default_mappings, PlasoToSiberianMapping


def _make_plaso_csv(content: str) -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


def _make_case_template() -> Path:
    template = {
        "schema_version": "siberian-case-v1",
        "context": {
            "os_profile": "windows",
            "os_release": "Windows 10",
            "system_build": "19045.3693",
            "scope": "host:test / Security.evtx",
            "interval_start": "2026-10-01T00:00:00+00:00",
            "interval_end": "2026-10-02T00:00:00+00:00",
            "acquisition_ref": "case://acquisition/security.evtx",
        },
        "activities": [
            {"action": "process_execution", "observations": []}
        ],
    }
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(template, f)
    f.close()
    return Path(f.name)


def test_default_mappings_target_valid_catalog_entries():
    """All default mappings must target existing catalog entries."""
    importer = PlasoImporter(mappings=get_default_mappings())
    # If invalid, constructor raises ValueError
    assert importer.mappings


def test_import_creates_present_observations():
    """Matched rows create PRESENT observations with evidence refs."""
    csv_content = """date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra
2026-10-01,12:00:00,UTC,M.....,Microsoft-Windows-Security-Auditing,Security,4688,SYSTEM,HOST,Process Created,New process,2,,,,,
2026-10-01,12:05:00,UTC,M.....,Microsoft-Windows-Security-Auditing,Security,5156,SYSTEM,HOST,Connection Permitted,Permitted conn,0,,,,,
"""
    csv_path = _make_plaso_csv(csv_content)
    template_path = _make_case_template()
    out_path = Path(tempfile.mktemp(suffix=".json"))

    importer = PlasoImporter(mappings=get_default_mappings())
    case, diagnostics = importer.import_file(csv_path, template_path, out_path)

    assert diagnostics.matched_rows == 2
    assert diagnostics.unknown_conditions_created == 2
    assert diagnostics.unmatched_rows == 0

    # Check enriched case
    activities = {a["action"]: a for a in case["activities"]}
    proc_obs = activities["process_execution"]["observations"]
    net_obs = activities["permitted_network_connection"]["observations"]
    assert len(proc_obs) == 1
    assert proc_obs[0]["artifact_type"] == "security_event_4688"
    assert proc_obs[0]["status"] == "unknown"
    assert proc_obs[0]["reason"] == "conditions_unverified"
    assert proc_obs[0]["evidence_ref"].startswith("case://import/plaso/")
    assert len(net_obs) == 1
    assert net_obs[0]["artifact_type"] == "security_event_5156"
    assert net_obs[0]["status"] == "unknown"
    assert net_obs[0]["reason"] == "conditions_unverified"


def test_unmatched_rows_are_diagnostics_not_states():
    """Unmatched rows appear in diagnostics, not as artifact states."""
    csv_content = """date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra
2026-10-01,12:00:00,UTC,M.....,Microsoft-Windows-Security-Auditing,Security,4688,SYSTEM,HOST,Process Created,New process,2,,,,,
2026-10-01,12:05:00,UTC,M.....,Unknown-Source,Security,9999,User,HOST,Unknown,Unknown event,0,,,,,
"""
    csv_path = _make_plaso_csv(csv_content)
    template_path = _make_case_template()
    out_path = Path(tempfile.mktemp(suffix=".json"))

    importer = PlasoImporter(mappings=get_default_mappings())
    case, diagnostics = importer.import_file(csv_path, template_path, out_path)

    assert diagnostics.matched_rows == 1
    assert diagnostics.unmatched_rows == 1
    assert len(diagnostics.unmatched_sample) == 1
    assert diagnostics.unmatched_sample[0]["type"] == "9999"
    # Enriched case should only have the matched observation
    proc_obs = case["activities"][0]["observations"]
    assert len(proc_obs) == 1


def test_duplicate_rows_for_same_artifact_do_not_duplicate_observations():
    """Multiple matching rows for same catalog entry create one UNKNOWN."""
    csv_content = """date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra
2026-10-01,12:00:00,UTC,M.....,Microsoft-Windows-Security-Auditing,Security,4688,SYSTEM,HOST,Process Created,New process,2,,,,,
2026-10-01,12:01:00,UTC,M.....,Microsoft-Windows-Security-Auditing,Security,4688,SYSTEM,HOST,Process Created,Another process,2,,,,,
"""
    csv_path = _make_plaso_csv(csv_content)
    template_path = _make_case_template()
    out_path = Path(tempfile.mktemp(suffix=".json"))

    importer = PlasoImporter(mappings=get_default_mappings())
    case, diagnostics = importer.import_file(csv_path, template_path, out_path)

    assert diagnostics.matched_rows == 2
    assert diagnostics.unknown_conditions_created == 1  # deduplicated
    proc_obs = case["activities"][0]["observations"]
    assert len(proc_obs) == 1
    assert proc_obs[0]["status"] == "unknown"
    assert proc_obs[0]["reason"] == "conditions_unverified"


def test_malformed_csv_rejected():
    """Malformed rows are rejected with error."""
    csv_content = """date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra
2026-10-01,12:00:00,UTC,M.....,Microsoft-Windows-Security-Auditing,Security,4688,SYSTEM,HOST,Process Created,New process,2,,,,,
2026-10-01,12:05:00,UTC,M.....,Only,Five,Fields,Here,Short,Desc,,,,,
"""
    csv_path = _make_plaso_csv(csv_content)
    template_path = _make_case_template()
    out_path = Path(tempfile.mktemp(suffix=".json"))

    importer = PlasoImporter(mappings=get_default_mappings())
    case, diagnostics = importer.import_file(csv_path, template_path, out_path)

    assert diagnostics.rejected_rows == 1
    assert len(diagnostics.errors) >= 1


def test_ambiguous_mapping_raises():
    """Two mappings matching same row raises ValueError."""
    mappings = [
        PlasoToSiberianMapping(
            source="Microsoft-Windows-Security-Auditing",
            sourcetype="Security",
            type="4688",
            activity="process_execution",
            artifact_type="security_event_4688",
        ),
        PlasoToSiberianMapping(
            source="Microsoft-Windows-Security-Auditing",
            sourcetype="Security",
            type="4688",
            activity="permitted_network_connection",
            artifact_type="security_event_5156",
        ),
    ]
    csv_content = """date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra
2026-10-01,12:00:00,UTC,M.....,Microsoft-Windows-Security-Auditing,Security,4688,User,Host,Short,Desc,0,,,,,
"""
    csv_path = _make_plaso_csv(csv_content)
    template_path = _make_case_template()
    out_path = Path(tempfile.mktemp(suffix=".json"))

    importer = PlasoImporter(mappings=mappings)
    case, diagnostics = importer.import_file(csv_path, template_path, out_path)

    assert diagnostics.mapping_errors >= 1
    assert "Ambiguous mapping" in diagnostics.errors[0]


def test_input_hash_in_diagnostics():
    """Diagnostics include SHA-256 of input file."""
    csv_content = """date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra
2026-10-01,12:00:00,UTC,M.....,Microsoft-Windows-Security-Auditing,Security,4688,SYSTEM,HOST,Process Created,New process,2,,,,,
"""
    csv_path = _make_plaso_csv(csv_content)
    template_path = _make_case_template()
    out_path = Path(tempfile.mktemp(suffix=".json"))

    importer = PlasoImporter(mappings=get_default_mappings())
    case, diagnostics = importer.import_file(csv_path, template_path, out_path)

    assert len(diagnostics.input_hash) == 64
    assert all(c in "0123456789abcdef" for c in diagnostics.input_hash)


def test_unsupported_format_rejected():
    """CSV with wrong headers is rejected."""
    csv_content = """wrong,headers,here
val1,val2,val3
"""
    csv_path = _make_plaso_csv(csv_content)
    template_path = _make_case_template()
    out_path = Path(tempfile.mktemp(suffix=".json"))

    importer = PlasoImporter(mappings=get_default_mappings())
    try:
        importer.import_file(csv_path, template_path, out_path)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Unsupported or malformed" in str(e)


def test_import_provenance_preserved():
    """Input file hash and row identity preserved in evidence_ref."""
    csv_content = """date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra
2026-10-01,12:00:00,UTC,M.....,Microsoft-Windows-Security-Auditing,Security,4688,SYSTEM,HOST,Process Created,New process,2,,,,,
"""
    csv_path = _make_plaso_csv(csv_content)
    template_path = _make_case_template()
    out_path = Path(tempfile.mktemp(suffix=".json"))

    importer = PlasoImporter(mappings=get_default_mappings())
    case, diagnostics = importer.import_file(csv_path, template_path, out_path)

    obs = case["activities"][0]["observations"][0]
    assert obs["evidence_ref"] == "case://import/plaso/row-1/process_execution/security_event_4688"
    # Hash is deterministic for same content
    assert len(diagnostics.input_hash) == 64
    assert all(c in "0123456789abcdef" for c in diagnostics.input_hash)


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
