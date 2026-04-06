# macOS Target Mapper (MTM)

MTM is a local attack surface mapping for macOS. It recursively walks the
filesystem, identifies Mach-O binaries, captures file metadata and code-signing
entitlement (XML), stores the results in SQLite, and includes browser-based
views for exploring the collected data.

## Commands

MTM currently exposes three workflows:

- `scan`: Walk the filesystem and write results into SQLite.
- `gui`: Launch the local browser view backed by the SQLite database.
- `export-html`: Generate a single standalone HTML view with embedded data.

Show the full command list with:

```bash
python3 -m mtm --help
```

## Run a scan

The scan command must run as `root`.

```bash
sudo python3 -m mtm scan --db /tmp/mtm.sqlite3
```

Resume a previous unfinished scan:

```bash
sudo python3 -m mtm scan --db /tmp/mtm.sqlite3 --resume
```

## Browser view

Open the local browser view against a completed or in-progress scan database:

```bash
python3 -m mtm gui --db /tmp/mtm.sqlite3
```

Preselect a specific scan:

```bash
python3 -m mtm gui --db /tmp/mtm.sqlite3 --scan-id <1337>
```

The live view:

- Displays all rows matching the active filters.
- Lets you filter by permission, entitlement state, path, and
  entitlement key.
- Opens details in a popup with metadata, entitlements XML, and extraction
  errors when present.

## Export a static browser view

Write a single self-contained HTML file with the scan data embedded as JSON so
it can be opened directly in a browser without a local MTM server:

```bash
python3 -m mtm export-html --db /tmp/mtm.sqlite3 --output /tmp/mtm-viewer.html
```

Preselect a scan in the exported viewer:

```bash
python3 -m mtm export-html --db /tmp/mtm.sqlite3 --output /tmp/mtm-viewer.html --scan-id <1337>
```

## Typical workflow

1. Run a scan into SQLite with `sudo python3 -m mtm scan --db ...`.
2. Review it locally with `python3 -m mtm gui --db ...`.
3. Generate a portable review artifact with `python3 -m mtm export-html --db ... --output ...`.

## Requirements

- macOS (and `python3`)
- `root` privileges via `sudo` for `scan`
- `/usr/bin/codesign`