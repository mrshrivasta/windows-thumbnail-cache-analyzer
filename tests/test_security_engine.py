"""Tests for the Security Engine and Detection Rules — Windows Thumbnail
Cache Analyzer.

Two layers of tests:
  1. Rule-level unit tests against synthetic context dicts (no file I/O).
  2. Engine-level tests that build REAL, spec-conformant CMMM thumbcache
     bytes with struct.pack, write them to a real temp .db file, and run
     the actual ScanEngine against them (no mocking of the parser).
"""
import os
import struct
import tempfile
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import ScanEngine, detect_image_format
from app.detection_rules import (
    rule_sensitive_identifier_path,
    rule_missing_identifier,
    rule_removable_or_network_identifier_path,
    rule_unrecognized_embedded_image_format,
    rule_known_cache_type,
    rule_unrecognized_thumbcache_format,
)

# A real minimal 2x2 JPEG-magic-prefixed blob (only the magic bytes matter
# for detect_image_format; the parser never tries to fully decode images).
JPEG_MAGIC_BLOB = b"\xff\xd8\xff\xe0" + b"\x00" * 16
PNG_MAGIC_BLOB = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
BMP_MAGIC_BLOB = b"BM" + b"\x00" * 16
NOT_AN_IMAGE_BLOB = b"NOTREALIMAGEDATA" * 2


# ---------------------------------------------------------------------------
# Rule-level unit tests (synthetic context dicts)
# ---------------------------------------------------------------------------

def test_rule_sensitive_identifier_path_hits():
    ctx = {"cache_file": "thumbcache_256.db", "entry_index": 3,
           "identifier": r"C:\Users\alice\Documents\tax_return_2024.pdf"}
    result = rule_sensitive_identifier_path(ctx)
    assert result is not None
    assert result["rule_id"] == "WTC-001"


def test_rule_sensitive_identifier_path_no_hit_on_clean_path():
    ctx = {"cache_file": "thumbcache_256.db", "entry_index": 1,
           "identifier": r"C:\Users\alice\Pictures\vacation.jpg"}
    assert rule_sensitive_identifier_path(ctx) is None


def test_rule_missing_identifier_hits_when_absent():
    ctx = {"cache_file": "thumbcache_96.db", "entry_index": 2,
           "identifier": None, "signature_ok": True,
           "image_format": "jpeg", "data_size": 500}
    result = rule_missing_identifier(ctx)
    assert result is not None
    assert result["rule_id"] == "WTC-002"


def test_rule_missing_identifier_no_hit_when_present():
    ctx = {"cache_file": "thumbcache_96.db", "entry_index": 2,
           "identifier": r"C:\pics\a.jpg", "signature_ok": True}
    assert rule_missing_identifier(ctx) is None


def test_rule_removable_or_network_identifier_path_usb():
    ctx = {"cache_file": "thumbcache_32.db", "entry_index": 0,
           "identifier": r"E:\backup\photo.jpg"}
    result = rule_removable_or_network_identifier_path(ctx)
    assert result is not None
    assert result["rule_id"] == "WTC-003"


def test_rule_removable_or_network_identifier_path_unc():
    ctx = {"cache_file": "thumbcache_32.db", "entry_index": 0,
           "identifier": r"\\fileserver\share\report.jpg"}
    result = rule_removable_or_network_identifier_path(ctx)
    assert result is not None
    assert result["rule_id"] == "WTC-003"


def test_rule_removable_or_network_identifier_path_c_drive_no_hit():
    ctx = {"cache_file": "thumbcache_32.db", "entry_index": 0,
           "identifier": r"C:\Users\bob\file.jpg"}
    assert rule_removable_or_network_identifier_path(ctx) is None


def test_rule_unrecognized_embedded_image_format_hits():
    ctx = {"cache_file": "thumbcache_256.db", "entry_index": 5,
           "data_size": 32, "image_format": "unknown"}
    result = rule_unrecognized_embedded_image_format(ctx)
    assert result is not None
    assert result["rule_id"] == "WTC-004"


def test_rule_unrecognized_embedded_image_format_no_hit_for_jpeg():
    ctx = {"cache_file": "thumbcache_256.db", "entry_index": 5,
           "data_size": 32, "image_format": "jpeg"}
    assert rule_unrecognized_embedded_image_format(ctx) is None


def test_rule_known_cache_type():
    ctx = {"cache_file": "thumbcache_256.db", "cache_type": 2}
    result = rule_known_cache_type(ctx)
    assert result is not None
    assert result["rule_id"] == "WTC-005"
    assert "256" in result["description"]


def test_rule_known_cache_type_unknown_value_no_hit():
    ctx = {"cache_file": "thumbcache_x.db", "cache_type": 99}
    assert rule_known_cache_type(ctx) is None


def test_rule_unrecognized_thumbcache_format_hits():
    ctx = {"cache_file": "not_a_thumbcache.db", "entry_index": 0, "signature_ok": False}
    result = rule_unrecognized_thumbcache_format(ctx)
    assert result is not None
    assert result["rule_id"] == "WTC-006"


def test_rule_unrecognized_thumbcache_format_no_hit_when_signature_ok():
    ctx = {"cache_file": "thumbcache_256.db", "entry_index": 0, "signature_ok": True}
    assert rule_unrecognized_thumbcache_format(ctx) is None


def test_detect_image_format_magic_bytes():
    assert detect_image_format(JPEG_MAGIC_BLOB) == "jpeg"
    assert detect_image_format(PNG_MAGIC_BLOB) == "png"
    assert detect_image_format(BMP_MAGIC_BLOB) == "bmp"
    assert detect_image_format(NOT_AN_IMAGE_BLOB) == "unknown"


# ---------------------------------------------------------------------------
# Engine-level tests: build REAL spec-conformant CMMM bytes with struct.pack
# ---------------------------------------------------------------------------

HEADER_STRUCT = struct.Struct("<4sIIIII")  # sig, version, cache_type, cache_off, avail_off, count
ENTRY_LEADER_STRUCT = struct.Struct("<4sI")  # sig, entry_size
ENTRY_FIXED_STRUCT = struct.Struct("<QIII8sQQ")
ENTRY_MIN_TOTAL = ENTRY_LEADER_STRUCT.size + ENTRY_FIXED_STRUCT.size  # 52


def _build_entry(identifier_text, data_bytes):
    """Real-build one spec-conformant CMMM entry, returning its raw bytes."""
    identifier_bytes = identifier_text.encode("utf-16-le") + b"\x00\x00" if identifier_text else b""
    padding_bytes = b""
    entry_size = ENTRY_MIN_TOTAL + len(identifier_bytes) + len(padding_bytes) + len(data_bytes)

    fixed = ENTRY_FIXED_STRUCT.pack(
        0xDEADBEEFCAFEBABE & 0xFFFFFFFFFFFFFFFF,  # Hash
        len(identifier_bytes),                    # IdentifierSize
        len(padding_bytes),                        # PaddingSize
        len(data_bytes),                            # DataSize
        b"\x00" * 8,                                 # Width/Height or reserved
        0,                                            # DataChecksum
        0,                                             # HeaderChecksum
    )
    leader = ENTRY_LEADER_STRUCT.pack(b"CMMM", entry_size)
    return leader + fixed + identifier_bytes + padding_bytes + data_bytes


def _build_thumbcache_file(entries, cache_type=2, version=0x14):
    header_size = HEADER_STRUCT.size
    header = HEADER_STRUCT.pack(b"CMMM", version, cache_type, header_size, header_size, len(entries))
    body = b"".join(entries)
    return header + body


def test_engine_parses_real_sensitive_identifier_entry():
    tmpdir = tempfile.mkdtemp()
    try:
        entry_sensitive = _build_entry(
            r"C:\Users\alice\Documents\my_password_vault.kdbx",
            JPEG_MAGIC_BLOB,
        )
        entry_no_identifier = _build_entry(None, PNG_MAGIC_BLOB)
        entry_bad_data = _build_entry(r"C:\Users\alice\Pictures\weird.dat", NOT_AN_IMAGE_BLOB)

        raw = _build_thumbcache_file([entry_sensitive, entry_no_identifier, entry_bad_data])
        target = os.path.join(tmpdir, "thumbcache_256.db")
        with open(target, "wb") as f:
            f.write(raw)

        engine = ScanEngine(target)
        result = engine.run()

        assert result["errors_count"] == 0
        assert result["files_scanned"] == 3  # 3 real entries parsed

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WTC-001" in rule_ids  # sensitive identifier
        assert "WTC-002" in rule_ids  # missing identifier
        assert "WTC-004" in rule_ids  # unrecognized embedded image format
        assert "WTC-005" in rule_ids  # known cache type (256)

        sensitive_findings = [f for f in result["findings"] if f["rule_id"] == "WTC-001"]
        assert "password" in sensitive_findings[0]["permissions_octal"].lower() or \
            "kdbx" in sensitive_findings[0]["permissions_octal"].lower()
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_removable_drive_identifier():
    tmpdir = tempfile.mkdtemp()
    try:
        entry = _build_entry(r"E:\photos\summer.jpg", BMP_MAGIC_BLOB)
        raw = _build_thumbcache_file([entry], cache_type=0)
        target = os.path.join(tmpdir, "thumbcache_32.db")
        with open(target, "wb") as f:
            f.write(raw)

        engine = ScanEngine(target)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WTC-003" in rule_ids
        assert result["files_scanned"] == 1
    finally:
        shutil.rmtree(tmpdir)


def test_engine_handles_unrecognized_signature_without_crashing():
    tmpdir = tempfile.mkdtemp()
    try:
        target = os.path.join(tmpdir, "thumbcache_bad.db")
        with open(target, "wb") as f:
            f.write(b"NOTC" + b"\x00" * 60)  # wrong signature entirely

        engine = ScanEngine(target)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WTC-006" in rule_ids
        assert result["errors_count"] >= 1
    finally:
        shutil.rmtree(tmpdir)


def test_engine_walks_directory_of_thumbcache_files():
    tmpdir = tempfile.mkdtemp()
    try:
        entry = _build_entry(r"C:\Users\bob\Desktop\secret_plans.png", PNG_MAGIC_BLOB)
        raw = _build_thumbcache_file([entry], cache_type=1)
        target = os.path.join(tmpdir, "thumbcache_96.db")
        with open(target, "wb") as f:
            f.write(raw)
        # Non-thumbcache file in same directory must be ignored, not crash.
        with open(os.path.join(tmpdir, "unrelated.txt"), "w") as f:
            f.write("hello")

        engine = ScanEngine(tmpdir)
        result = engine.run()

        assert result["dirs_scanned"] >= 1
        assert result["files_scanned"] == 1
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WTC-001" in rule_ids  # "secret" pattern
    finally:
        shutil.rmtree(tmpdir)


def test_engine_truncated_file_reports_error_not_crash():
    tmpdir = tempfile.mkdtemp()
    try:
        target = os.path.join(tmpdir, "thumbcache_1024.db")
        with open(target, "wb") as f:
            f.write(b"CMMM" + b"\x00" * 4)  # valid sig, way too short for a header

        engine = ScanEngine(target)
        result = engine.run()
        assert isinstance(result["findings"], list)
    finally:
        shutil.rmtree(tmpdir)


def test_engine_missing_path_counts_error_not_crash():
    engine = ScanEngine("/nonexistent/path/does/not/exist.db")
    result = engine.run()
    assert result["errors_count"] >= 1
    assert result["findings"] == []
