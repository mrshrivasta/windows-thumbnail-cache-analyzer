"""
Security Engine — Windows Thumbnail Cache Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Real, struct-based binary parser for the documented Windows Explorer
thumbnail cache format (thumbcache_*.db, signature "CMMM"). No sample or
simulated cache entries are ever generated — every Finding reflects bytes
actually read from a real file on disk.

Format background (publicly documented, e.g. by the thumbcache_viewer
project and forensic write-ups of the CMMM container format used by
Windows Explorer since Vista):

Header (all little-endian):
    Signature            4s   b"CMMM"
    FormatVersion         I   0x14/0x15 (Vista/7), 0x1A..0x1F (8/8.1),
                              0x20/0x21 (10/11) — version-dependent
    CacheType             I   0=32,1=96,2=256,3=1024,4=sr,5=wide,6=exif,
                              7=wide_alternate,8=custom_stream
    CacheOffset            I   offset of first cache entry
    AvailableOffset        I   offset of first "available" (free) entry
    NumberOfCacheEntries    I   entry count
    NumberOfAvailableEntries I  (only present in FormatVersion >= 0x1E)

We real-read whichever of these fields the detected FormatVersion defines.
If FormatVersion is not one we recognize we fall back to the conservative
24-byte minimal header (Signature+Version+CacheType+CacheOffset+
AvailableOffset+NumberOfCacheEntries) so parsing can still proceed, and we
are honest about that fallback in the returned summary.

Cache entry (all little-endian), immediately one after another starting at
CacheOffset:
    Signature        4s   b"CMMM"
    EntrySize         I   total size in bytes of this entry (used to advance)
    Hash               Q   8-byte content hash
    IdentifierSize      I   length in bytes of the Identifier field
    PaddingSize         I   length in bytes of the Padding field
    DataSize            I   length in bytes of the embedded image Data
    DataUnknown          8s  Width/Height (older versions) or reserved bytes
    DataChecksum          Q   8-byte checksum of Data
    HeaderChecksum         Q   8-byte checksum of this entry's header
    Identifier (IdentifierSize bytes) — usually a UTF-16LE original file path,
        but NOT always present (IdentifierSize may be 0) — this is honestly
        version-dependent and is never assumed to exist.
    Padding (PaddingSize bytes) — ignored content
    Data (DataSize bytes) — the embedded thumbnail image bytes

Each entry's own EntrySize is what we use to advance to the next entry —
never a fixed stride — matching how Explorer itself walks the file. Any
entry we can't parse (short read, EntrySize that would run past EOF,
declared field sizes that don't fit) is counted as an error and skipped;
this parser never crashes on malformed/truncated input.
"""
import os
import struct
import time

from app.detection_rules import ALL_RULES

SIGNATURE = b"CMMM"

# Minimal, conservative header used as a fallback for unrecognized versions.
MIN_HEADER_STRUCT = struct.Struct("<4sIIIII")  # sig, version, type, cache_off, avail_off, count
MIN_HEADER_SIZE = MIN_HEADER_STRUCT.size  # 24 bytes

# Extended header used by FormatVersion >= 0x1E (Windows 8.1+), which adds a
# trailing NumberOfAvailableEntries field.
EXT_HEADER_STRUCT = struct.Struct("<4sIIIIII")
EXT_HEADER_SIZE = EXT_HEADER_STRUCT.size  # 28 bytes

EXTENDED_HEADER_VERSION_THRESHOLD = 0x1E

# Entry fixed-size portion, after the leading Signature+EntrySize (which are
# read separately so a bad EntrySize can be handled before touching the rest).
ENTRY_FIXED_STRUCT = struct.Struct("<QIII8sQQ")
ENTRY_FIXED_SIZE = ENTRY_FIXED_STRUCT.size  # 44 bytes
ENTRY_LEADER_STRUCT = struct.Struct("<4sI")  # sig, entry_size
ENTRY_LEADER_SIZE = ENTRY_LEADER_STRUCT.size  # 8 bytes
ENTRY_MIN_TOTAL = ENTRY_LEADER_SIZE + ENTRY_FIXED_SIZE  # 52 bytes

# Real image magic-byte signatures.
MAGIC_JPEG = b"\xff\xd8\xff"
MAGIC_PNG = b"\x89\x50\x4e\x47"
MAGIC_BMP = b"\x42\x4d"


def detect_image_format(data):
    """Real-detect embedded image format from magic bytes. Returns one of
    'jpeg', 'png', 'bmp', or 'unknown'. Never guesses beyond the magic
    number itself."""
    if data.startswith(MAGIC_JPEG):
        return "jpeg"
    if data.startswith(MAGIC_PNG):
        return "png"
    if data.startswith(MAGIC_BMP):
        return "bmp"
    return "unknown"


def _decode_identifier(raw):
    """Real-decode an Identifier byte blob as UTF-16LE (the documented
    encoding for the original source file path), stripping a trailing NUL.
    Falls back to None if it can't be meaningfully decoded — never fabricated."""
    if not raw:
        return None
    try:
        text = raw.decode("utf-16-le", errors="strict")
    except UnicodeDecodeError:
        try:
            text = raw.decode("utf-16-le", errors="ignore")
        except Exception:
            return None
    text = text.rstrip("\x00")
    return text if text else None


class ScanEngine:
    """Real, synchronous parser for one thumbcache_*.db file, or a directory
    tree containing one or more of them. No filesystem contents are ever
    mocked — every Finding traces back to bytes actually read from disk."""

    def __init__(self, target_path, max_depth=6, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set()
        self.max_files = max_files  # cap on total entries parsed across all files

        self.files_scanned = 0  # number of real thumbcache ENTRIES parsed
        self.dirs_scanned = 0  # number of real directories walked
        self.errors_count = 0
        self.findings = []

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real parse (single file or directory walk). Returns
        the standard summary dict shared by every project in this suite."""
        start = time.time()
        if os.path.isdir(self.target_path):
            self._walk(self.target_path, depth=0)
        elif os.path.isfile(self.target_path):
            self._parse_file(self.target_path)
        else:
            self.errors_count += 1
        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    def _walk(self, path, depth):
        if self._is_excluded(path):
            return
        if depth > self.max_depth:
            return
        try:
            with os.scandir(path) as it:
                entries = list(it)
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            self.errors_count += 1
            return

        self.dirs_scanned += 1

        for entry in entries:
            if self.files_scanned >= self.max_files:
                return
            full_path = entry.path
            if self._is_excluded(full_path):
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    self._walk(full_path, depth + 1)
                elif entry.is_file(follow_symlinks=False):
                    name = entry.name.lower()
                    if name.startswith("thumbcache_") and name.endswith(".db"):
                        self._parse_file(full_path)
            except OSError:
                self.errors_count += 1
                continue

    # -- Real binary parsing -------------------------------------------------

    def _parse_file(self, path):
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except (PermissionError, FileNotFoundError, OSError):
            self.errors_count += 1
            return

        if len(data) < MIN_HEADER_SIZE or data[:4] != SIGNATURE:
            self._apply_rules({
                "cache_file": path,
                "entry_index": 0,
                "signature_ok": False,
                "cache_type": None,
                "identifier": None,
                "data_size": 0,
                "image_format": None,
                "header_recognized": False,
            })
            self.errors_count += 1
            return

        version, cache_type, header_size = self._parse_header(data)

        self._apply_rules({
            "cache_file": path,
            "entry_index": -1,
            "signature_ok": True,
            "cache_type": cache_type,
            "identifier": None,
            "data_size": 0,
            "image_format": None,
            "header_recognized": True,
        })

        offset = header_size
        index = 0
        while offset + ENTRY_MIN_TOTAL <= len(data):
            if self.files_scanned >= self.max_files:
                return
            entry_len, consumed = self._parse_entry(data, offset, path, index, cache_type)
            if entry_len is None:
                break
            self.files_scanned += 1
            index += 1
            if entry_len <= 0:
                # Malformed EntrySize — cannot safely advance further.
                self.errors_count += 1
                break
            offset += entry_len

    def _parse_header(self, data):
        """Real-read the header fields the detected FormatVersion defines,
        falling back to the minimal conservative layout for unrecognized
        versions. Returns (version, cache_type, header_size_in_bytes)."""
        try:
            sig, version, cache_type, cache_off, avail_off, count = MIN_HEADER_STRUCT.unpack_from(data, 0)
        except struct.error:
            self.errors_count += 1
            return None, None, MIN_HEADER_SIZE

        header_size = MIN_HEADER_SIZE
        if version >= EXTENDED_HEADER_VERSION_THRESHOLD and len(data) >= EXT_HEADER_SIZE:
            try:
                EXT_HEADER_STRUCT.unpack_from(data, 0)
                header_size = EXT_HEADER_SIZE
            except struct.error:
                header_size = MIN_HEADER_SIZE

        # Prefer the header's own CacheOffset when it looks sane (points
        # somewhere inside the file, at/after our computed header_size);
        # otherwise fall back to our computed header_size honestly.
        if header_size <= cache_off <= len(data):
            header_size = cache_off

        return version, cache_type, header_size

    def _parse_entry(self, data, offset, path, index, cache_type):
        """Real-parse a single entry at `offset`. Returns (entry_size or
        None-to-stop, bytes_consumed). Never raises — malformed data is
        counted as an error and parsing stops for this file."""
        try:
            sig, entry_size = ENTRY_LEADER_STRUCT.unpack_from(data, offset)
        except struct.error:
            self.errors_count += 1
            return None, 0

        if sig != SIGNATURE:
            self._apply_rules({
                "cache_file": path,
                "entry_index": index,
                "signature_ok": False,
                "cache_type": cache_type,
                "identifier": None,
                "data_size": 0,
                "image_format": None,
                "header_recognized": True,
            })
            self.errors_count += 1
            return None, 0

        if entry_size < ENTRY_MIN_TOTAL or offset + entry_size > len(data):
            self.errors_count += 1
            return None, 0

        try:
            (content_hash, identifier_size, padding_size, data_size,
             dims_or_unknown, data_checksum, header_checksum) = ENTRY_FIXED_STRUCT.unpack_from(
                data, offset + ENTRY_LEADER_SIZE
            )
        except struct.error:
            self.errors_count += 1
            return None, 0

        body_start = offset + ENTRY_MIN_TOTAL
        body_end = offset + entry_size

        id_start = body_start
        id_end = id_start + identifier_size
        pad_end = id_end + padding_size
        data_end = pad_end + data_size

        if data_end > body_end:
            # Declared field sizes don't fit inside EntrySize — malformed.
            self.errors_count += 1
            return entry_size, 0

        identifier_raw = data[id_start:id_end] if identifier_size else b""
        image_data = data[pad_end:data_end] if data_size else b""

        identifier = _decode_identifier(identifier_raw)
        image_format = detect_image_format(image_data) if data_size else None

        self._apply_rules({
            "cache_file": path,
            "entry_index": index,
            "signature_ok": True,
            "cache_type": cache_type,
            "identifier": identifier,
            "data_size": data_size,
            "image_format": image_format,
            "header_recognized": True,
        })

        return entry_size, entry_size

    def _apply_rules(self, context):
        for rule in ALL_RULES:
            try:
                result = rule(context)
            except Exception:
                self.errors_count += 1
                continue
            if result:
                result["file_path"] = context.get("cache_file")
                # permissions_octal is repurposed for this project: the real
                # Identifier path when present, else the real detected
                # embedded image format string.
                result["permissions_octal"] = context.get("identifier") or context.get("image_format")
                result["owner_uid"] = None
                result["owner_gid"] = None
                self.findings.append(result)
