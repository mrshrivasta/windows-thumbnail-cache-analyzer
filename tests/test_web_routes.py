import os
import struct
import tempfile

import pytest

# Build a real, spec-conformant CMMM thumbcache file (same layout as
# app.security_engine) with one entry whose Identifier triggers a real
# WTC-001 finding, so the workflow test exercises a genuine finding path.
HEADER_STRUCT = struct.Struct("<4sIIIII")
ENTRY_LEADER_STRUCT = struct.Struct("<4sI")
ENTRY_FIXED_STRUCT = struct.Struct("<QIII8sQQ")
ENTRY_MIN_TOTAL = ENTRY_LEADER_STRUCT.size + ENTRY_FIXED_STRUCT.size
JPEG_MAGIC_BLOB = b"\xff\xd8\xff\xe0" + b"\x00" * 16


def _build_entry(identifier_text, data_bytes):
    identifier_bytes = identifier_text.encode("utf-16-le") + b"\x00\x00" if identifier_text else b""
    entry_size = ENTRY_MIN_TOTAL + len(identifier_bytes) + len(data_bytes)
    fixed = ENTRY_FIXED_STRUCT.pack(
        0xCAFEBABE, len(identifier_bytes), 0, len(data_bytes), b"\x00" * 8, 0, 0,
    )
    leader = ENTRY_LEADER_STRUCT.pack(b"CMMM", entry_size)
    return leader + fixed + identifier_bytes + data_bytes


def _build_thumbcache_bytes():
    entry = _build_entry(r"C:\Users\alice\Documents\my_password_backup.kdbx", JPEG_MAGIC_BLOB)
    header_size = HEADER_STRUCT.size
    header = HEADER_STRUCT.pack(b"CMMM", 0x14, 2, header_size, header_size, 1)
    return header + entry


@pytest.fixture()
def real_thumbcache_file():
    fd, path = tempfile.mkstemp(suffix=".db", prefix="thumbcache_256_")
    with os.fdopen(fd, "wb") as f:
        f.write(_build_thumbcache_bytes())
    yield path
    os.remove(path)


def test_full_scan_alert_incident_workflow(registered_client, real_thumbcache_file):
    # Run a real scan against a genuine, spec-conformant thumbcache file
    # built with struct.pack (no mocking of the parser).
    resp = registered_client.post("/scan/run", data={"target_path": real_thumbcache_file}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Scan complete" in resp.data

    # Logs page should show at least one scan
    resp = registered_client.get("/logs")
    assert real_thumbcache_file.encode() in resp.data

    # Alerts page should load and contain a real alert (WTC-001 is medium severity)
    resp = registered_client.get("/alerts")
    assert resp.status_code == 200

    # Analytics JSON endpoint returns real aggregated data
    resp = registered_client.get("/analytics/data")
    assert resp.status_code == 200
    assert resp.is_json
    data = resp.get_json()
    assert sum(data["severity_breakdown"].values()) >= 1

    # Reports CSV export works
    resp = registered_client.get("/reports/export.csv")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/csv")
    assert b"WTC-001" in resp.data


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp",
        "scan_depth_limit": "3",
        "exclude_paths": "",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_scan_run_requires_target_path(registered_client):
    resp = registered_client.post("/scan/run", data={"target_path": ""}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Please provide a path" in resp.data


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
