"""
Detection Rules — Windows Thumbnail Cache Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects a REAL parsed thumbcache entry (as produced by
app.security_engine.ScanEngine from real CMMM-format bytes on disk) and
returns a Finding dict if the condition is met. Rules take a single
`context` dict so they can be unit-tested with synthetic data without
touching any real file.

context keys used by these rules (all populated from REAL parsed bytes
when run through the engine):
    cache_file          - path to the thumbcache_*.db file being parsed
    entry_index         - 0-based index of the entry within the file
    signature_ok         - bool, True if the entry/header started with b"CMMM"
    cache_type           - int, real CacheType field from the header (or None)
    identifier            - str or None, real decoded Identifier (usually the
                            original source file path, UTF-16LE-decoded) or
                            None if IdentifierSize was 0 / entry had none
    data_size             - int, real DataSize field
    image_format          - str, one of "jpeg", "png", "bmp", "unknown", or
                            None if data_size == 0
    header_recognized     - bool, True if the file/entry started with CMMM
                            and a version-dependent header layout was matched

Rules are pure functions: given the same context they always return the
same result, and they never touch the filesystem themselves — only the
Security Engine reads real bytes from disk.
"""

# Severity scale used consistently across the whole project
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

SENSITIVE_PATTERNS = (
    "password", "passwd", "secret", "confidential", ".kdbx",
    "passport", "ssn", "tax",
)

# Real, documented thumbcache CacheType -> nominal pixel size categories.
# (Source: publicly documented thumbcache_*.db naming/CacheType conventions
# used by Windows Explorer since Vista/7.)
KNOWN_CACHE_TYPES = {
    0: "32x32 (thumbcache_32.db)",
    1: "96x96 (thumbcache_96.db)",
    2: "256x256 (thumbcache_256.db)",
    3: "1024x1024 (thumbcache_1024.db)",
    4: "sr (system-restricted, thumbcache_sr.db)",
    5: "wide (thumbcache_wide.db)",
    6: "exif (thumbcache_exif.db)",
    7: "wide_alternate (thumbcache_wide_alternate.db)",
    8: "custom_stream (thumbcache_custom_stream.db)",
}


def rule_sensitive_identifier_path(context):
    """WTC-001: The entry's Identifier (original source-file path recovered
    from the cache) contains a sensitive keyword/extension (password,
    secret, confidential, .kdbx, passport, ssn, tax). Forensic relevance:
    a thumbnail cache entry proves Windows Explorer rendered/viewed the
    referenced file at some point, even if that file has since been
    deleted — this is strong evidence of user access to sensitive material."""
    identifier = context.get("identifier")
    if not identifier:
        return None
    lowered = identifier.lower()
    for pattern in SENSITIVE_PATTERNS:
        if pattern in lowered:
            return {
                "rule_id": "WTC-001",
                "rule_name": "Sensitive File Referenced in Thumbnail Cache",
                "severity": SEVERITY_MEDIUM,
                "description": (
                    f"Entry #{context.get('entry_index')} in "
                    f"{context.get('cache_file')} has an Identifier "
                    f"referencing '{pattern}' ({identifier}). Explorer "
                    f"rendered a thumbnail for this file, proving it was "
                    f"present and viewed even if later deleted."
                ),
            }
    return None


def rule_missing_identifier(context):
    """WTC-002: The entry has NO Identifier (IdentifierSize == 0 or absent).
    This is common and expected in some CacheType/version layouts — the
    embedded thumbnail image itself may still be forensically recoverable
    and viewable, but its original source path cannot be determined from
    this entry alone. Reported as low/informational so the examiner knows
    to correlate by content Hash instead."""
    if context.get("entry_index", -1) < 0:
        return None  # header-level context marker, not a real entry
    if context.get("identifier"):
        return None
    if not context.get("signature_ok"):
        return None
    image_format = context.get("image_format")
    data_size = context.get("data_size") or 0
    return {
        "rule_id": "WTC-002",
        "rule_name": "Thumbnail Entry Without Recoverable Source Path",
        "severity": SEVERITY_LOW,
        "description": (
            f"Entry #{context.get('entry_index')} in "
            f"{context.get('cache_file')} has no Identifier — the source "
            f"file path is not recoverable from this entry alone. Embedded "
            f"image format: {image_format or 'none'}, size: {data_size} "
            f"bytes. Correlate by content Hash against other evidence."
        ),
    }


def rule_removable_or_network_identifier_path(context):
    """WTC-003: The Identifier path references a removable drive (any
    letter other than C:) or a UNC network path (\\\\server\\share\\...).
    Forensic relevance: indicates the viewed file originated from external
    media (USB stick, SD card) or a network share rather than the local
    system drive — relevant to exfiltration/removable-media investigations."""
    identifier = context.get("identifier")
    if not identifier:
        return None
    is_unc = identifier.startswith("\\\\") or identifier.startswith("//")
    is_removable_drive = False
    if len(identifier) >= 2 and identifier[1] == ":":
        drive = identifier[0].upper()
        if drive != "C":
            is_removable_drive = True
    if is_unc or is_removable_drive:
        kind = "UNC network path" if is_unc else "non-system drive letter"
        return {
            "rule_id": "WTC-003",
            "rule_name": "Thumbnail References Removable/Network Path",
            "severity": SEVERITY_LOW,
            "description": (
                f"Entry #{context.get('entry_index')} in "
                f"{context.get('cache_file')} has an Identifier ({identifier}) "
                f"indicating a {kind}. The source file was likely on "
                f"removable media or a network share, not the local system drive."
            ),
        }
    return None


def rule_unrecognized_embedded_image_format(context):
    """WTC-004: DataSize is nonzero but the embedded Data bytes do not begin
    with a recognized image magic number (JPEG FF D8 FF, PNG 89 50 4E 47,
    or BMP 42 4D). Forensic relevance: may indicate corruption, a non-image
    payload, or deliberate cache-poisoning/anti-forensic tampering and
    warrants manual carving/review of the raw bytes."""
    data_size = context.get("data_size") or 0
    image_format = context.get("image_format")
    if data_size > 0 and image_format == "unknown":
        return {
            "rule_id": "WTC-004",
            "rule_name": "Unrecognized Embedded Image Format",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"Entry #{context.get('entry_index')} in "
                f"{context.get('cache_file')} has {data_size} bytes of "
                f"embedded Data that do not match any known image magic "
                f"number (JPEG/PNG/BMP). Possible corruption or "
                f"cache-poisoning — recommend manual review of raw bytes."
            ),
        }
    return None


def rule_known_cache_type(context):
    """WTC-005: The header's CacheType field maps to a documented,
    known thumbcache size category (32/96/256/1024/sr/wide/exif/
    wide_alternate/custom_stream). Informational — records which physical
    thumbcache_*.db this data most likely originated from for chain-of-
    custody notes."""
    cache_type = context.get("cache_type")
    if cache_type is None:
        return None
    label = KNOWN_CACHE_TYPES.get(cache_type)
    if label is None:
        return None
    return {
        "rule_id": "WTC-005",
        "rule_name": "Known Thumbcache CacheType",
        "severity": SEVERITY_LOW,
        "description": (
            f"{context.get('cache_file')} header CacheType={cache_type} "
            f"corresponds to the documented category '{label}'."
        ),
    }


def rule_unrecognized_thumbcache_format(context):
    """WTC-006: The leading 4 bytes of the file (or an entry boundary) did
    not match the real CMMM signature. Forensic relevance: the file may not
    be a Windows thumbcache database at all (wrong file, renamed, or
    corrupted/truncated), or it may use a variant this parser does not yet
    understand. Reported honestly rather than guessing at a layout."""
    if context.get("signature_ok"):
        return None
    return {
        "rule_id": "WTC-006",
        "rule_name": "Unrecognized Thumbcache Signature",
        "severity": SEVERITY_LOW,
        "description": (
            f"{context.get('cache_file')} (entry #{context.get('entry_index')}) "
            f"did not begin with the expected 'CMMM' signature. This may not "
            f"be a valid thumbcache_*.db file, or the region is corrupted/"
            f"truncated. Parsing stopped at this point rather than guessing."
        ),
    }


ALL_RULES = [
    rule_sensitive_identifier_path,
    rule_missing_identifier,
    rule_removable_or_network_identifier_path,
    rule_unrecognized_embedded_image_format,
    rule_known_cache_type,
    rule_unrecognized_thumbcache_format,
]
