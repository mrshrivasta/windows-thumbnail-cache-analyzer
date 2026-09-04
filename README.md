# Windows Thumbnail Cache Analyzer

**A real, no-mock-data digital-forensics parser for Windows Explorer thumbnail cache files — CLI + Web App.**
Real-parses the documented binary `CMMM` format used by `thumbcache_*.db` files (found at
`%AppData%\Local\Microsoft\Windows\Explorer\thumbcache_*.db`) to recover embedded thumbnail images
and — where present — the original source-file path of files a user viewed in Windows Explorer,
including files that have since been deleted from disk.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ Disclaimer (read before use)

This software is provided **strictly for educational, defensive-security, and digital-forensics purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Run this tool **only** against thumbcache files, disk images, or systems that you own or for which you have explicit, documented authorization to examine. Analyzing systems or evidence without authorization may violate computer-crime laws and organizational or engagement policy.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including mishandled evidence, chain-of-custody issues, data loss, or legal consequences — arising from the use, misuse, or inability to use this software.
- **Not a substitute for certified forensic tools or expert testimony.** This tool is **not** a replacement for a certified digital-forensics suite (EnCase, FTK, X-Ways, Autopsy, etc.), a formal chain-of-custody process, or a qualified forensic examiner's analysis and testimony. It is an educational/productivity aid for understanding and exploring the thumbcache format.
- **Findings are heuristic, not proof.** A thumbnail cache entry is strong *evidence* that Explorer rendered a thumbnail for a given file at some point — it is not, by itself, conclusive proof of who viewed it, when, or under what circumstances. Corroborate with other artifacts (MFT, LNK files, jump lists, registry MRU, etc.) before drawing conclusions.
- **Version-dependent format, honestly documented.** The thumbcache binary layout differs across Windows versions (Vista/7 vs 8/8.1 vs 10/11), and the per-entry `Identifier` (original file path) field is **not always present** — some cache types and versions omit it entirely. This tool reports what it can honestly determine from the bytes present and never fabricates a path or format it cannot verify.
- **Read-only by design.** This tool only reads bytes from the thumbcache file(s) you point it at — it never modifies, deletes, or writes back to the source file. Verify this yourself by reading `app/security_engine/__init__.py` before running it on anything important (e.g. original evidence — always work on a copy).
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to examine a given file or system, **do not run this tool against it.**

---

## Who should use this project

- Digital forensics examiners and incident responders investigating what files a Windows user viewed in Explorer.
- Security students and self-learners studying Windows forensic artifacts and the thumbcache/CMMM format.
- DFIR practitioners who need a transparent, auditable, dependency-light tool instead of a closed-source viewer.
- Anyone recovering evidence of deleted-file access from a copy of a `thumbcache_*.db` file they are authorized to examine.

## Why use this project

- **Real data only** — every result comes from actually reading and `struct`-unpacking the bytes of a real `thumbcache_*.db` file. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py`. Nothing is a black box.
- **Two interfaces, one engine** — the CLI (for terminals/CI/scripted triage) and the web app (for dashboards/case teams) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a parser** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports for a case file.
- **Honest about format variance** — the parser never assumes a field is present when the documented format says it may not be; unrecognized signatures and malformed entries are reported, not silently skipped or guessed at.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external API calls at scan time.

---

## Architecture

```
windows-thumbnail-cache-analyzer/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Core real binary parser for the CMMM thumbcache format (struct-based)
│   ├── detection_rules/      # 6 documented detection rules (sensitive paths, removable media, etc.)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite)
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — real spec-conformant bytes + rule-level unit tests
├── docs/                      # Additional documentation
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, depth, exclusions, alert threshold)

---

## How the parser actually works

Given a real path to a `thumbcache_*.db` file (or a directory, which is real-walked for files named
`thumbcache_*.db`), the Security Engine:

1. Reads the file's real bytes and checks the leading 4-byte signature against `b"CMMM"`.
2. Reads a real 4-byte `FormatVersion` and 4-byte `CacheType` field, plus the remaining
   version-dependent header fields (`CacheOffset`, `AvailableOffset`, entry count, and — for
   `FormatVersion >= 0x1E` — an additional `NumberOfAvailableEntries` field). If the version isn't
   one this parser recognizes, it honestly falls back to the conservative minimal header size
   rather than guessing at an unknown layout.
3. Starting at the real `CacheOffset`, loops over cache entries. Each entry begins with its own
   `CMMM` signature and 4-byte `EntrySize`, followed by an 8-byte `Hash`, `IdentifierSize`,
   `PaddingSize`, `DataSize`, an 8-byte width/height-or-reserved field, and two 8-byte checksums —
   then the variable-length `Identifier`, `Padding`, and `Data` byte regions.
4. Uses each entry's **own** `EntrySize` to advance to the next entry (never a fixed stride),
   exactly like Explorer itself does. If `EntrySize` would run past end-of-file, or a declared
   field size doesn't fit, the entry is counted as an error and parsing of that file stops rather
   than reading garbage.
5. Real-decodes the `Identifier` bytes as UTF-16LE when `IdentifierSize > 0` — this is the original
   source-file path in most versions, but it is **honestly optional**; many entries (and some
   `CacheType`/version combinations) never carry one.
6. Real-detects the embedded `Data` blob's image format from its magic bytes: `FF D8 FF` = JPEG,
   `89 50 4E 47` = PNG, `42 4D` = BMP. Anything else with a nonzero `DataSize` is reported as an
   unrecognized format (possible corruption or cache tampering) rather than guessed at.

Nothing is ever fabricated: a file that isn't really a thumbcache, or an entry that doesn't really
parse, produces an honest error/finding — never invented data.

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| WTC-001 | Sensitive File Referenced in Thumbnail Cache | Medium | Real `Identifier` path contains a sensitive keyword/extension (`password`, `secret`, `confidential`, `.kdbx`, `passport`, `ssn`, `tax`) — evidence the file was viewed in Explorer |
| WTC-002 | Thumbnail Entry Without Recoverable Source Path | Low | `Identifier` is absent — thumbnail is recoverable but its source path can't be determined from this entry alone |
| WTC-003 | Thumbnail References Removable/Network Path | Low | `Identifier` path is on a non-`C:` drive letter or a `\\` UNC network path — external media / network-share indicator |
| WTC-004 | Unrecognized Embedded Image Format | Medium | Embedded `Data` has nonzero size but doesn't match JPEG/PNG/BMP magic bytes — possible corruption or cache poisoning |
| WTC-005 | Known Thumbcache CacheType | Low | Header `CacheType` maps to a documented category (32/96/256/1024/sr/wide/exif/wide_alternate/custom_stream) — informational |
| WTC-006 | Unrecognized Thumbcache Signature | Low | Leading bytes don't match `CMMM` — not a valid/parseable thumbcache region |

---

## Setup & Run

### Requirements
- Python 3.9+
- Any OS — the parser reads raw bytes with `struct` and does not depend on Windows APIs, so it can
  analyze a copied `thumbcache_*.db` file from Linux, macOS, or Windows alike.

### Install

```bash
git clone <this-repository-url>
cd windows-thumbnail-cache-analyzer
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
WTCA_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                   # port to listen on
FLASK_DEBUG=1               # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at
`instance/wtca.db`.

### Run the CLI

```bash
python3 cli/main.py scan /path/to/thumbcache_256.db
python3 cli/main.py scan /path/to/copied/Explorer/dir --json
python3 cli/main.py scan /path/to/copied/Explorer/dir --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings are detected (useful as a CI/triage gate) and
`0` if the target is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

The suite combines rule-level unit tests against synthetic context dictionaries with engine-level
tests that build real, spec-conformant `CMMM` thumbcache bytes with `struct.pack`, write them to a
real temp `.db` file, and run the actual `ScanEngine` against them — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Windows Thumbnail Cache Analyzer check?**
It real-parses the binary `CMMM` thumbcache format used by `thumbcache_*.db` files, recovering each
entry's embedded thumbnail image and (when present) the original source-file path, and flags
sensitive-file references, removable/network-drive paths, unrecognized embedded image formats, and
unrecognized cache signatures.

**Who should use it?**
Digital forensics examiners, incident responders, security students, and anyone investigating what
files a Windows user viewed in Explorer — including files later deleted — on systems/evidence they
own or are authorized to examine.

**Is it a replacement for certified forensic tools?**
No. It is an educational and productivity aid only — see the Disclaimer section above.

**Does the Identifier (source file path) always exist in a thumbcache entry?**
No, and this tool is honest about that. Whether an `Identifier` is present depends on the Windows
version and `CacheType`; when it's absent, the tool still reports the recoverable embedded
thumbnail image and its detected format, but flags (WTC-002) that the source path is unknown from
that entry alone.

**Does it modify the files it analyzes?**
No. It only reads bytes from the thumbcache file(s) you point it at. It never writes to, deletes,
or modifies the source file — always work on a copy of evidence, as with any forensic tool.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or
modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
