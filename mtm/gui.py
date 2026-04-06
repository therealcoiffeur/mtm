"""Browser-based viewer for MTM scan results."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Iterable
from urllib.parse import quote
from urllib.parse import parse_qs, urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import webbrowser
from xml.dom import minidom

from mtm.models import BinaryDetails, BinaryFilter, BinaryListItem, ViewerScanSummary

PERMISSION_FILTERS: tuple[tuple[str, str], ...] = (
    ("All permissions", "all"),
    ("Setuid", "setuid"),
    ("Setgid", "setgid"),
    ("Sticky bit", "sticky"),
    ("Group writable", "group_writable"),
    ("World writable", "world_writable"),
)

ENTITLEMENT_FILTERS: tuple[tuple[str, str], ...] = (
    ("All entitlement states", "all"),
    ("Has entitlements", "has_entitlements"),
    ("No entitlements", "no_entitlements"),
    ("Unsigned", "unsigned"),
    ("Extraction error", "error"),
    ("Empty entitlement set", "none"),
    ("Extracted", "extracted"),
)


def launch_gui(db_path: Path, *, initial_scan_id: int | None = None) -> int:
    """Launch the browser-based viewer."""

    return launch_browser_viewer(
        db_path,
        initial_scan_id=initial_scan_id,
    )


def launch_browser_viewer(
    db_path: Path,
    *,
    initial_scan_id: int | None = None,
) -> int:
    """Serve a local browser UI for browsing scan results."""

    server = _ViewerHTTPServer(
        db_path=db_path,
        initial_scan_id=initial_scan_id,
    )
    host, port = server.server_address
    viewer_url = f"http://{host}:{port}/"
    print("Starting the local browser viewer.")
    print(f"Viewer URL: {viewer_url}")
    print("Press Ctrl-C to stop the local viewer server.")

    try:
        webbrowser.open_new_tab(viewer_url)
    except Exception:
        pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def export_static_html(
    db_path: Path,
    output_path: Path,
    *,
    initial_scan_id: int | None = None,
) -> Path:
    """Write a self-contained browser viewer with embedded scan data."""

    dataset = _build_static_dataset(db_path)
    html = _render_browser_html(
        initial_scan_id=initial_scan_id,
        viewer_mode="static",
        embedded_data=dataset,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path


def list_scans(db_path: Path) -> list[ViewerScanSummary]:
    """Return the scans stored in the database, newest first."""

    with _open_read_only_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                started_at,
                ended_at,
                root_path,
                status,
                total_binaries_identified,
                total_extraction_failures
            FROM scans
            ORDER BY id DESC
            """
        ).fetchall()
    return [
        ViewerScanSummary(
            scan_id=row["id"],
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            root_path=row["root_path"],
            status=row["status"],
            total_binaries_identified=row["total_binaries_identified"],
            total_extraction_failures=row["total_extraction_failures"],
        )
        for row in rows
    ]


def query_binaries(db_path: Path, filters: BinaryFilter) -> tuple[int, list[BinaryListItem]]:
    """Return the total match count and full result rows for the GUI table."""

    count_sql, count_params, data_sql, data_params = build_binary_query(filters)
    with _open_read_only_connection(db_path) as connection:
        total_matches = int(connection.execute(count_sql, count_params).fetchone()["match_count"])
        rows = connection.execute(data_sql, data_params).fetchall()

    items = [
        BinaryListItem(
            binary_id=row["binary_id"],
            scan_id=row["scan_id"],
            path=row["path"],
            real_path=row["real_path"],
            mode_octal=row["mode_octal"],
            mode_symbolic=row["mode_symbolic"],
            uid=row["uid"],
            gid=row["gid"],
            has_entitlements=bool(row["has_entitlements"]),
            entitlement_extraction_status=row["entitlement_extraction_status"],
            is_universal=bool(row["is_universal"]),
        )
        for row in rows
    ]
    return total_matches, items


def get_binary_details(db_path: Path, binary_id: int) -> BinaryDetails | None:
    """Load full detail for a single binary row."""

    with _open_read_only_connection(db_path) as connection:
        row = connection.execute(
            """
            SELECT
                b.id AS binary_id,
                b.scan_id,
                b.path,
                b.real_path,
                b.root_path,
                b.file_type,
                b.binary_reason,
                b.is_macho,
                b.is_universal,
                b.mode_octal,
                b.mode_symbolic,
                b.uid,
                b.gid,
                b.size,
                b.inode,
                b.device,
                b.mtime,
                b.ctime,
                b.has_entitlements,
                b.entitlement_extraction_status,
                b.entitlement_extraction_error,
                b.discovered_at,
                e.entitlements_xml
            FROM binaries AS b
            LEFT JOIN entitlements AS e
                ON e.binary_id = b.id
            WHERE b.id = ?
            """,
            (binary_id,),
        ).fetchone()
        if row is None:
            return None
        error_rows = connection.execute(
            """
            SELECT stage, error_type, message, stderr, created_at
            FROM errors
            WHERE binary_id = ?
            ORDER BY id ASC
            """,
            (binary_id,),
        ).fetchall()

    return BinaryDetails(
        binary_id=row["binary_id"],
        scan_id=row["scan_id"],
        path=row["path"],
        real_path=row["real_path"],
        root_path=row["root_path"],
        file_type=row["file_type"],
        binary_reason=row["binary_reason"],
        is_macho=bool(row["is_macho"]),
        is_universal=bool(row["is_universal"]),
        mode_octal=row["mode_octal"],
        mode_symbolic=row["mode_symbolic"],
        uid=row["uid"],
        gid=row["gid"],
        size=row["size"],
        inode=row["inode"],
        device=row["device"],
        mtime=row["mtime"],
        ctime=row["ctime"],
        has_entitlements=bool(row["has_entitlements"]),
        entitlement_extraction_status=row["entitlement_extraction_status"],
        entitlement_extraction_error=row["entitlement_extraction_error"],
        discovered_at=row["discovered_at"],
        entitlements_xml=row["entitlements_xml"],
        entitlements_display_xml=_format_entitlements_for_display(row["entitlements_xml"]),
        error_text=_format_error_text(error_rows),
    )


def build_binary_query(filters: BinaryFilter) -> tuple[str, list[object], str, list[object]]:
    """Build the count and data queries for the current binary filters."""

    clauses = ["1 = 1"]
    params: list[object] = []
    join_entitlements = False

    if filters.scan_id is not None:
        clauses.append("b.scan_id = ?")
        params.append(filters.scan_id)
    if filters.path_contains.strip():
        clauses.append("b.path LIKE ? ESCAPE '\\'")
        params.append(_like_contains(filters.path_contains.strip()))

    permission_sql = _permission_filter_clause(filters.permission_filter)
    if permission_sql is not None:
        clauses.append(permission_sql)

    entitlement_sql = _entitlement_filter_clause(filters.entitlement_filter)
    if entitlement_sql is not None:
        clauses.append(entitlement_sql)

    if filters.entitlement_key_contains.strip():
        join_entitlements = True
        clauses.append("e.entitlements_xml LIKE ? ESCAPE '\\'")
        params.append(_like_contains(filters.entitlement_key_contains.strip()))

    # Only join the entitlements table when the active filters actually need it.
    join_sql = "LEFT JOIN entitlements AS e ON e.binary_id = b.id" if join_entitlements else ""
    where_sql = " AND ".join(clauses)
    count_sql = f"""
        SELECT COUNT(*) AS match_count
        FROM binaries AS b
        {join_sql}
        WHERE {where_sql}
    """
    data_sql = f"""
        SELECT
            b.id AS binary_id,
            b.scan_id,
            b.path,
            b.real_path,
            b.mode_octal,
            b.mode_symbolic,
            b.uid,
            b.gid,
            b.has_entitlements,
            b.entitlement_extraction_status,
            b.is_universal
        FROM binaries AS b
        {join_sql}
        WHERE {where_sql}
        ORDER BY b.path ASC
    """
    data_params = list(params)
    return count_sql, params, data_sql, data_params


def _permission_filter_clause(filter_name: str) -> str | None:
    """Return the SQL clause for the selected permission filter."""

    clauses = {
        "all": None,
        "setuid": "(b.mode_bits & 2048) != 0",
        "setgid": "(b.mode_bits & 1024) != 0",
        "sticky": "(b.mode_bits & 512) != 0",
        "group_writable": "(b.mode_bits & 16) != 0",
        "world_writable": "(b.mode_bits & 2) != 0",
    }
    if filter_name not in clauses:
        raise ValueError(f"unsupported permission filter: {filter_name}")
    return clauses[filter_name]


def _entitlement_filter_clause(filter_name: str) -> str | None:
    """Return the SQL clause for the selected entitlement filter."""

    clauses = {
        "all": None,
        "has_entitlements": "b.has_entitlements = 1",
        "no_entitlements": "b.has_entitlements = 0",
        "unsigned": "b.entitlement_extraction_status = 'unsigned'",
        "error": "b.entitlement_extraction_status = 'error'",
        "none": "b.entitlement_extraction_status = 'none'",
        "extracted": "b.entitlement_extraction_status = 'extracted'",
    }
    if filter_name not in clauses:
        raise ValueError(f"unsupported entitlement filter: {filter_name}")
    return clauses[filter_name]


def _like_contains(value: str) -> str:
    """Escape a string for a LIKE contains match."""

    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _open_read_only_connection(db_path: Path) -> sqlite3.Connection:
    """Open the SQLite database in read-only mode."""

    if not db_path.exists():
        raise FileNotFoundError(f"database not found: {db_path}")
    uri_path = quote(str(db_path), safe="/")
    connection = sqlite3.connect(f"file:{uri_path}?mode=ro", uri=True, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def _format_entitlements_for_display(raw_xml: str | None) -> str | None:
    """Pretty-print entitlement XML for the GUI while preserving raw storage."""

    if raw_xml is None:
        return None

    stripped = raw_xml.strip()
    if not stripped:
        return None

    try:
        pretty = minidom.parseString(stripped.encode("utf-8")).toprettyxml(indent="  ")
    except Exception:
        return stripped

    # minidom inserts blank text-node lines, so collapse them back out for display.
    normalized_lines = [line for line in pretty.splitlines() if line.strip()]
    return "\n".join(normalized_lines)


def _format_error_text(error_rows: Iterable[sqlite3.Row]) -> str:
    """Collapse structured error rows into the viewer's text block format."""

    error_blocks: list[str] = []
    for error_row in error_rows:
        lines = [
            f"[{error_row['created_at']}] {error_row['stage']} {error_row['error_type']}",
            error_row["message"],
        ]
        if error_row["stderr"]:
            lines.append(error_row["stderr"])
        error_blocks.append("\n".join(lines))
    return "\n\n".join(error_blocks)


def _build_static_dataset(db_path: Path) -> dict[str, object]:
    """Load the full viewer dataset for embedding into a static export."""

    with _open_read_only_connection(db_path) as connection:
        scan_rows = connection.execute(
            """
            SELECT
                id,
                started_at,
                ended_at,
                root_path,
                status,
                total_binaries_identified,
                total_extraction_failures
            FROM scans
            ORDER BY id DESC
            """
        ).fetchall()
        binary_rows = connection.execute(
            """
            SELECT
                b.id AS binary_id,
                b.scan_id,
                b.path,
                b.real_path,
                b.root_path,
                b.file_type,
                b.binary_reason,
                b.is_macho,
                b.is_universal,
                b.mode_octal,
                b.mode_symbolic,
                b.uid,
                b.gid,
                b.size,
                b.inode,
                b.device,
                b.mtime,
                b.ctime,
                b.has_entitlements,
                b.entitlement_extraction_status,
                b.entitlement_extraction_error,
                b.discovered_at,
                e.entitlements_xml
            FROM binaries AS b
            LEFT JOIN entitlements AS e
                ON e.binary_id = b.id
            ORDER BY b.path ASC
            """
        ).fetchall()
        error_rows = connection.execute(
            """
            SELECT binary_id, stage, error_type, message, stderr, created_at
            FROM errors
            WHERE binary_id IS NOT NULL
            ORDER BY binary_id ASC, id ASC
            """
        ).fetchall()

    errors_by_binary_id: dict[int, list[sqlite3.Row]] = {}
    for error_row in error_rows:
        binary_id = int(error_row["binary_id"])
        errors_by_binary_id.setdefault(binary_id, []).append(error_row)

    scans = [
        asdict(
            ViewerScanSummary(
                scan_id=row["id"],
                started_at=row["started_at"],
                ended_at=row["ended_at"],
                root_path=row["root_path"],
                status=row["status"],
                total_binaries_identified=row["total_binaries_identified"],
                total_extraction_failures=row["total_extraction_failures"],
            )
        )
        for row in scan_rows
    ]
    binaries = []
    for row in binary_rows:
        details = BinaryDetails(
            binary_id=row["binary_id"],
            scan_id=row["scan_id"],
            path=row["path"],
            real_path=row["real_path"],
            root_path=row["root_path"],
            file_type=row["file_type"],
            binary_reason=row["binary_reason"],
            is_macho=bool(row["is_macho"]),
            is_universal=bool(row["is_universal"]),
            mode_octal=row["mode_octal"],
            mode_symbolic=row["mode_symbolic"],
            uid=row["uid"],
            gid=row["gid"],
            size=row["size"],
            inode=row["inode"],
            device=row["device"],
            mtime=row["mtime"],
            ctime=row["ctime"],
            has_entitlements=bool(row["has_entitlements"]),
            entitlement_extraction_status=row["entitlement_extraction_status"],
            entitlement_extraction_error=row["entitlement_extraction_error"],
            discovered_at=row["discovered_at"],
            entitlements_xml=row["entitlements_xml"],
            entitlements_display_xml=_format_entitlements_for_display(row["entitlements_xml"]),
            error_text=_format_error_text(errors_by_binary_id.get(int(row["binary_id"]), [])),
        )
        binaries.append(asdict(details))

    return {
        "meta": {
            "source_db": str(db_path),
            "exported_at": datetime.now(timezone.utc).isoformat(),
        },
        "scans": scans,
        "binaries": binaries,
    }


class _ViewerHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server carrying viewer configuration."""

    daemon_threads = True

    def __init__(self, *, db_path: Path, initial_scan_id: int | None) -> None:
        super().__init__(("127.0.0.1", 0), _ViewerHTTPRequestHandler)
        self.db_path = db_path
        self.initial_scan_id = initial_scan_id


class _ViewerHTTPRequestHandler(BaseHTTPRequestHandler):
    """Serve the local browser viewer and JSON APIs."""

    server: _ViewerHTTPServer

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)

        try:
            if parsed.path == "/":
                self._send_html(_build_browser_index_html(self.server.initial_scan_id))
                return

            if parsed.path == "/api/scans":
                payload = [asdict(scan) for scan in list_scans(self.server.db_path)]
                self._send_json(payload)
                return

            if parsed.path == "/api/binaries":
                filters = self._filters_from_query(parse_qs(parsed.query))
                total_matches, items = query_binaries(self.server.db_path, filters)
                self._send_json(
                    {
                        "total_matches": total_matches,
                        "items": [asdict(item) for item in items],
                    }
                )
                return

            if parsed.path.startswith("/api/binary/"):
                binary_id = int(parsed.path.rsplit("/", 1)[-1])
                details = get_binary_details(self.server.db_path, binary_id)
                if details is None:
                    self._send_json({"error": "binary not found"}, status=404)
                    return
                self._send_json(asdict(details))
                return

            self._send_json({"error": "not found"}, status=404)
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=400)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=500)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        """Keep the local server quiet unless something goes wrong."""

    def _filters_from_query(self, query: dict[str, list[str]]) -> BinaryFilter:
        scan_id = self._parse_optional_int(query.get("scan_id", [""])[0])
        return BinaryFilter(
            scan_id=scan_id,
            path_contains=query.get("path_contains", [""])[0],
            permission_filter=query.get("permission_filter", ["all"])[0] or "all",
            entitlement_filter=query.get("entitlement_filter", ["all"])[0] or "all",
            entitlement_key_contains=query.get("entitlement_key_contains", [""])[0],
        )

    def _parse_optional_int(self, value: str) -> int | None:
        if not value:
            return None
        return int(value)

    def _send_json(self, payload: object, *, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, body: str, *, status: int = 200) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def _build_browser_index_html(initial_scan_id: int | None) -> str:
    """Return the single-page browser viewer."""

    return _render_browser_html(
        initial_scan_id=initial_scan_id,
        viewer_mode="live",
        embedded_data=None,
    )


def _render_browser_html(
    *,
    initial_scan_id: int | None,
    viewer_mode: str,
    embedded_data: dict[str, object] | None,
) -> str:
    """Render the shared HTML template for live and static viewer modes."""

    html = _BROWSER_VIEWER_HTML.replace(
        "__INITIAL_SCAN_ID__",
        "null" if initial_scan_id is None else str(initial_scan_id),
    )
    html = html.replace("__VIEWER_MODE__", viewer_mode)
    html = html.replace("__EMBEDDED_DATA__", _json_for_html(embedded_data))
    return html


def _json_for_html(value: object) -> str:
    """Serialize JSON safely for direct embedding into an HTML script block."""

    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return (
        text.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


_BROWSER_VIEWER_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MTM</title>
  <style>
    :root {
      --bg: #f4ecdf;
      --panel: rgba(255, 252, 245, 0.9);
      --panel-strong: rgba(255, 255, 255, 0.94);
      --ink: #14262d;
      --muted: #58727a;
      --line: rgba(163, 153, 137, 0.28);
      --accent: #0d6c74;
      --accent-strong: #0a4d54;
      --accent-soft: rgba(13, 108, 116, 0.12);
      --accent-ghost: rgba(13, 108, 116, 0.08);
      --gold: #b47a1f;
      --good: #116b49;
      --good-soft: rgba(17, 107, 73, 0.12);
      --warn: #8a4b14;
      --warn-soft: rgba(138, 75, 20, 0.12);
      --danger: #a33535;
      --danger-soft: rgba(163, 53, 53, 0.12);
      --shadow: 0 24px 54px rgba(24, 35, 38, 0.1);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100dvh;
      font-family: "Avenir Next", "SF Pro Display", "Helvetica Neue", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(13, 108, 116, 0.18), transparent 28rem),
        radial-gradient(circle at 88% 12%, rgba(180, 122, 31, 0.14), transparent 26rem),
        linear-gradient(180deg, #f7f2e8 0%, var(--bg) 54%, #efe5d7 100%);
      color: var(--ink);
      overflow-x: hidden;
    }
    .shell {
      width: min(100%, 1680px);
      min-height: 100dvh;
      margin: 0 auto;
      padding: clamp(12px, 2vw, 24px);
      display: grid;
      gap: clamp(14px, 1.5vw, 18px);
      grid-template-rows: auto auto minmax(0, 1fr);
    }
    .hero, .filters, .content, .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 22px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(12px);
    }
    .hero {
      padding: clamp(18px, 2vw, 24px);
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: end;
      gap: 16px;
      background:
        linear-gradient(140deg, rgba(255, 255, 255, 0.82), rgba(255, 251, 242, 0.9)),
        radial-gradient(circle at top right, rgba(13, 108, 116, 0.12), transparent 20rem);
      overflow: hidden;
      position: relative;
    }
    .hero::after {
      content: "";
      position: absolute;
      right: -28px;
      top: -34px;
      width: 170px;
      height: 170px;
      border-radius: 999px;
      background: radial-gradient(circle, rgba(13, 108, 116, 0.18), transparent 70%);
      pointer-events: none;
    }
    .hero-copy {
      position: relative;
      z-index: 1;
      max-width: 70ch;
    }
    .eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 10px;
      color: var(--accent-strong);
      font-size: 0.8rem;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }
    .eyebrow::before {
      content: "";
      width: 34px;
      height: 1px;
      background: linear-gradient(90deg, rgba(13, 108, 116, 0.2), var(--accent));
    }
    .hero h1 {
      margin: 0 0 8px;
      font-size: clamp(1.5rem, 2.5vw, 2.35rem);
      letter-spacing: -0.04em;
    }
    .hero p {
      margin: 0;
      color: var(--muted);
      max-width: 70ch;
      line-height: 1.55;
    }
    .status-pill {
      padding: 11px 16px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent-strong);
      font-weight: 600;
      max-width: 100%;
      text-align: center;
      border: 1px solid rgba(13, 108, 116, 0.14);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.5);
      position: relative;
      z-index: 1;
    }
    .status-pill.status-good {
      background: var(--good-soft);
      color: var(--good);
      border-color: rgba(17, 107, 73, 0.16);
    }
    .status-pill.status-warn {
      background: var(--warn-soft);
      color: var(--warn);
      border-color: rgba(138, 75, 20, 0.18);
    }
    .status-pill.status-error {
      background: var(--danger-soft);
      color: var(--danger);
      border-color: rgba(163, 53, 53, 0.18);
    }
    .filters {
      padding: clamp(14px, 1.8vw, 18px);
      display: grid;
      gap: 14px;
      grid-template-columns: repeat(auto-fit, minmax(min(220px, 100%), 1fr));
      align-items: end;
      background:
        linear-gradient(180deg, rgba(255, 254, 250, 0.94), rgba(253, 249, 241, 0.92));
    }
    .filters-copy {
      grid-column: 1 / -1;
      display: grid;
      gap: 4px;
      margin-bottom: 2px;
    }
    .section-kicker {
      color: var(--accent-strong);
      font-size: 0.77rem;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }
    .filters-copy h2 {
      margin: 0;
      font-size: 1.1rem;
      letter-spacing: -0.03em;
    }
    .filters-copy p {
      margin: 0;
      color: var(--muted);
      line-height: 1.5;
    }
    .field {
      display: grid;
      gap: 6px;
      min-width: 0;
    }
    .field.scan-field,
    .field.path-field,
    .field.entitlement-key-field {
      grid-column: span 2;
    }
    .field label {
      font-size: 0.86rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
    }
    input, select, button {
      font: inherit;
      border-radius: 14px;
      border: 1px solid var(--line);
      padding: 12px 13px;
      background: rgba(255, 255, 255, 0.96);
      color: var(--ink);
      width: 100%;
      min-width: 0;
      transition: border-color 140ms ease, box-shadow 140ms ease, transform 140ms ease, background 140ms ease;
    }
    input:focus, select:focus {
      outline: 2px solid rgba(13, 108, 116, 0.16);
      border-color: var(--accent);
      box-shadow: 0 0 0 4px rgba(13, 108, 116, 0.08);
    }
    .actions {
      display: flex;
      align-items: end;
      justify-content: flex-end;
      gap: 10px;
      flex-wrap: wrap;
      grid-column: 1 / -1;
    }
    button {
      cursor: pointer;
      background: linear-gradient(180deg, #0f7780 0%, var(--accent) 100%);
      color: white;
      border-color: rgba(10, 77, 84, 0.35);
      font-weight: 600;
      width: auto;
      box-shadow: 0 12px 22px rgba(13, 108, 116, 0.22);
    }
    button:hover {
      transform: translateY(-1px);
      box-shadow: 0 16px 24px rgba(13, 108, 116, 0.24);
    }
    button.secondary {
      background: rgba(255, 255, 255, 0.7);
      color: var(--accent-strong);
      border-color: var(--line);
      box-shadow: none;
    }
    button.secondary:hover {
      background: rgba(255, 255, 255, 0.96);
      box-shadow: 0 10px 20px rgba(18, 34, 41, 0.08);
    }
    .content {
      padding: clamp(14px, 1.8vw, 18px);
      display: flex;
      min-height: min(62dvh, 980px);
      overflow: hidden;
      background:
        linear-gradient(180deg, rgba(255, 255, 255, 0.92), rgba(255, 251, 244, 0.9));
    }
    .table-wrap {
      display: flex;
      flex-direction: column;
      flex: 1;
      min-height: 0;
      overflow: hidden;
    }
    .table-meta {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
      margin-bottom: 14px;
      color: var(--muted);
      font-size: 0.95rem;
    }
    #results-count {
      color: var(--ink);
      font-size: 1rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    #results-note {
      color: var(--muted);
      text-align: right;
    }
    .table-shell {
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: var(--panel-strong);
      min-height: 0;
      flex: 1;
      max-width: 100%;
      overscroll-behavior: contain;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.7);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
      min-width: 0;
    }
    thead th {
      position: sticky;
      top: 0;
      background: linear-gradient(180deg, rgba(234, 245, 245, 0.98), rgba(247, 250, 247, 0.98));
      color: var(--accent-strong);
      font-size: 0.82rem;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      text-align: left;
      border-bottom: 1px solid rgba(13, 108, 116, 0.08);
    }
    th, td {
      padding: 14px 14px;
      border-bottom: 1px solid rgba(163, 153, 137, 0.16);
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    th:nth-child(1), td:nth-child(1) { width: 42%; }
    th:nth-child(2), td:nth-child(2) { width: 18%; }
    th:nth-child(3), td:nth-child(3) { width: 12%; }
    th:nth-child(4), td:nth-child(4) { width: 10%; }
    th:nth-child(5), td:nth-child(5) { width: 10%; }
    th:nth-child(6), td:nth-child(6) { width: 8%; }
    tbody tr {
      cursor: pointer;
      transition: background 140ms ease, transform 140ms ease, box-shadow 140ms ease;
    }
    tbody tr:hover {
      background: rgba(13, 108, 116, 0.04);
      box-shadow: inset 4px 0 0 rgba(13, 108, 116, 0.22);
    }
    tbody tr.selected {
      background: rgba(13, 108, 116, 0.08);
      box-shadow: inset 4px 0 0 rgba(13, 108, 116, 0.44);
    }
    .mono {
      font-family: "SF Mono", "Menlo", monospace;
      font-size: 0.92rem;
    }
    .row-path {
      color: var(--ink);
      font-weight: 700;
    }
    .row-secondary {
      margin-top: 4px;
      color: var(--muted);
      font-size: 0.82rem;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 0.8rem;
      font-weight: 700;
      letter-spacing: 0.01em;
      border: 1px solid transparent;
      white-space: nowrap;
    }
    .badge-good {
      color: var(--good);
      background: var(--good-soft);
      border-color: rgba(17, 107, 73, 0.14);
    }
    .badge-warn {
      color: var(--warn);
      background: var(--warn-soft);
      border-color: rgba(138, 75, 20, 0.16);
    }
    .badge-error {
      color: var(--danger);
      background: var(--danger-soft);
      border-color: rgba(163, 53, 53, 0.16);
    }
    .badge-neutral {
      color: var(--accent-strong);
      background: var(--accent-soft);
      border-color: rgba(13, 108, 116, 0.14);
    }
    .badge-muted {
      color: var(--muted);
      background: rgba(88, 114, 122, 0.1);
      border-color: rgba(88, 114, 122, 0.12);
    }
    .empty-row td {
      padding: 0;
      width: auto;
    }
    .empty-state {
      padding: 34px 24px;
      display: grid;
      gap: 8px;
      text-align: center;
      color: var(--muted);
    }
    .empty-state strong {
      color: var(--ink);
      font-size: 1rem;
    }
    .modal {
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 24px;
      background: rgba(18, 34, 41, 0.56);
      backdrop-filter: blur(8px);
      z-index: 999;
    }
    .modal.open {
      display: flex;
    }
    .modal-dialog {
      width: min(1100px, calc(100vw - 32px));
      max-height: min(90dvh, calc(100vh - 24px));
      display: flex;
      flex-direction: column;
      background: rgba(255, 252, 247, 0.98);
      border: 1px solid rgba(215, 210, 199, 0.9);
      border-radius: 26px;
      box-shadow: 0 32px 70px rgba(18, 34, 41, 0.28);
      overflow: hidden;
    }
    .modal-header {
      display: flex;
      align-items: start;
      justify-content: space-between;
      gap: 16px;
      padding: 18px 20px;
      border-bottom: 1px solid #e7e1d5;
      background:
        linear-gradient(180deg, rgba(237, 247, 247, 0.96), rgba(255, 252, 247, 0.98)),
        radial-gradient(circle at top right, rgba(13, 108, 116, 0.12), transparent 14rem);
    }
    .modal-title {
      min-width: 0;
    }
    .modal-title h2 {
      margin: 0 0 6px;
      font-size: 1.22rem;
      letter-spacing: -0.03em;
    }
    .modal-subtitle {
      color: var(--muted);
      font-size: 0.95rem;
      word-break: break-word;
    }
    .modal-close {
      width: auto;
      min-width: 44px;
      padding-inline: 14px;
      background: transparent;
      color: var(--accent-strong);
      border-color: var(--line);
      flex: 0 0 auto;
    }
    .modal-body {
      padding: clamp(14px, 1.8vw, 18px);
      overflow: auto;
    }
    .modal-grid {
      display: grid;
      gap: 16px;
      grid-template-columns: 1fr;
    }
    .card {
      padding: 16px;
      min-height: 0;
      display: flex;
      flex-direction: column;
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.92), rgba(255, 252, 247, 0.88));
    }
    .card h2 {
      margin: 0 0 10px;
      font-size: 1rem;
      letter-spacing: 0.02em;
    }
    pre {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: "SF Mono", "Menlo", monospace;
      font-size: 0.9rem;
      color: #203239;
      overflow: auto;
      min-height: 0;
      flex: 1;
    }
    .empty {
      color: var(--muted);
      font-style: italic;
    }
    .warning {
      color: var(--warn);
      font-weight: 600;
    }
    .hidden {
      display: none !important;
    }
    @media (max-width: 1320px) {
      .field.scan-field,
      .field.path-field,
      .field.entitlement-key-field {
        grid-column: span 1;
      }
      .modal-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
      .modal-grid .card:first-child {
        grid-column: 1 / -1;
      }
    }
    @media (max-width: 1100px) {
      .filters {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
      .content {
        min-height: min(58dvh, 860px);
      }
      .actions {
        justify-content: stretch;
      }
      .actions button {
        flex: 1 1 180px;
      }
      #results-note {
        width: 100%;
        text-align: left;
      }
    }
    @media (max-width: 920px) {
      .content {
        min-height: auto;
        overflow: visible;
      }
      .table-wrap {
        overflow: visible;
      }
      .table-shell {
        overflow: visible;
        background: transparent;
        border: none;
      }
      table {
        display: block;
      }
      thead {
        display: none;
      }
      tbody {
        display: grid;
        gap: 12px;
      }
      tbody tr {
        display: grid;
        gap: 10px;
        padding: 14px;
        border: 1px solid var(--line);
        border-radius: 16px;
        background: rgba(255, 255, 255, 0.96);
        box-shadow: 0 12px 26px rgba(18, 34, 41, 0.06);
      }
      tbody tr.result-row {
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 10px;
      }
      tbody tr.result-row td {
        display: flex;
        flex-direction: column;
        gap: 8px;
        padding: 12px;
        border: 1px solid rgba(163, 153, 137, 0.18);
        border-radius: 14px;
        width: auto;
        min-width: 0;
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(248, 244, 237, 0.94));
        align-items: flex-start;
      }
      tbody tr.result-row td[data-label="Path"] {
        grid-column: 1 / -1;
        padding: 0;
        border: none;
        border-bottom: 1px solid rgba(163, 153, 137, 0.18);
        border-radius: 0;
        background: transparent;
        padding-bottom: 12px;
      }
      tbody tr.result-row td::before {
        content: attr(data-label);
        color: var(--muted);
        font-size: 0.76rem;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        font-family: "Avenir Next", "SF Pro Display", "Helvetica Neue", sans-serif;
      }
      tbody tr.result-row td[data-label="Path"]::before {
        content: "Binary";
      }
      tbody tr.result-row .row-path {
        font-size: 0.98rem;
        line-height: 1.45;
      }
      tbody tr.result-row .row-secondary {
        margin-top: 0;
      }
      tbody tr.result-row .badge {
        max-width: 100%;
      }
      .empty-row {
        display: block;
        cursor: default;
      }
      .empty-row td {
        display: block;
      }
    }
    @media (max-width: 720px) {
      .shell {
        min-height: auto;
      }
      .hero {
        align-items: stretch;
      }
      .hero-copy {
        max-width: 100%;
      }
      .filters {
        grid-template-columns: 1fr;
      }
      .field.scan-field,
      .field.path-field,
      .field.entitlement-key-field,
      .actions {
        grid-column: span 1;
      }
      .table-meta {
        font-size: 0.9rem;
      }
      .modal {
        padding: 10px;
      }
      .modal-dialog {
        width: min(100vw - 20px, 100%);
        max-height: min(94dvh, 100%);
      }
      .modal-header,
      .modal-body {
        padding: 14px;
      }
      .modal-grid {
        grid-template-columns: 1fr;
      }
      .modal-header {
        flex-direction: column;
        align-items: stretch;
      }
      .modal-close {
        width: 100%;
      }
      .actions {
        justify-content: stretch;
      }
      .actions button {
        width: 100%;
      }
    }
    @media (max-width: 520px) {
      .status-pill {
        width: 100%;
        text-align: center;
      }
      .card {
        padding: 14px;
      }
      tbody tr.result-row {
        grid-template-columns: 1fr;
      }
      tbody tr.result-row td {
        padding: 10px 12px;
      }
      tbody tr.result-row td[data-label="Path"] {
        padding: 0 0 10px;
      }
      .modal-title h2 {
        font-size: 1.05rem;
      }
      pre {
        font-size: 0.83rem;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <div class="hero-copy">
        <h1>macOS Target Mapper</h1>
        <div class="eyebrow">Local Attack Surface Viewer</div>
      </div>
      <div class="status-pill" id="status-pill">Loading scan metadata...</div>
    </section>

    <section class="filters">
      <div class="filters-copy">
        <div class="section-kicker">Filters</div>
      </div>
      <div class="field scan-field">
        <label for="scan-select">Scan</label>
        <select id="scan-select"></select>
      </div>
      <div class="field">
        <label for="permission-select">Permission Filter</label>
        <select id="permission-select">
          <option value="all">All permissions</option>
          <option value="setuid">Setuid</option>
          <option value="setgid">Setgid</option>
          <option value="sticky">Sticky bit</option>
          <option value="group_writable">Group writable</option>
          <option value="world_writable">World writable</option>
        </select>
      </div>
      <div class="field">
        <label for="entitlement-select">Entitlement Filter</label>
        <select id="entitlement-select">
          <option value="all">All entitlement states</option>
          <option value="has_entitlements">Has entitlements</option>
          <option value="no_entitlements">No entitlements</option>
          <option value="unsigned">Unsigned</option>
          <option value="error">Extraction error</option>
          <option value="none">Empty entitlement set</option>
          <option value="extracted">Extracted</option>
        </select>
      </div>
      <div class="field path-field">
        <label for="path-input">Path Contains</label>
        <input id="path-input" type="text" placeholder="/Applications or ssh">
      </div>
      <div class="field entitlement-key-field">
        <label for="entitlement-input">Entitlement Key Contains</label>
        <input id="entitlement-input" type="text" placeholder="get-task-allow">
      </div>
      <div class="actions">
        <button id="apply-button" type="button">Apply Now</button>
        <button id="reset-button" class="secondary" type="button">Reset</button>
      </div>
    </section>

    <section class="content">
      <div class="table-wrap">
        <div class="table-meta">
          <div>
            <div class="section-kicker">Results</div>
            <div id="results-count">Waiting for results...</div>
          </div>
          <div id="results-note">Click any row to inspect metadata, entitlements, and extraction errors.</div>
        </div>
        <div class="table-shell">
          <table>
            <thead>
              <tr>
                <th>Path</th>
                <th>Mode</th>
                <th>UID:GID</th>
                <th>Status</th>
                <th>Entitlements</th>
                <th>Universal</th>
              </tr>
            </thead>
            <tbody id="results-body"></tbody>
          </table>
        </div>
      </div>
    </section>
  </div>

  <div class="modal" id="details-modal" aria-hidden="true">
    <div class="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div class="modal-header">
        <div class="modal-title">
          <h2 id="modal-title">Binary Details</h2>
          <div class="modal-subtitle" id="modal-subtitle"></div>
        </div>
        <button id="modal-close" class="modal-close" type="button" aria-label="Close details">Close</button>
      </div>
      <div class="modal-body">
        <div class="modal-grid">
          <section class="card" id="metadata-card">
            <h2>Metadata</h2>
            <pre id="metadata-panel" class="mono empty"></pre>
          </section>
          <section class="card hidden" id="entitlements-card">
            <h2>Entitlements XML</h2>
            <pre id="entitlements-panel" class="mono empty"></pre>
          </section>
          <section class="card hidden" id="errors-card">
            <h2>Errors</h2>
            <pre id="errors-panel" class="mono empty"></pre>
          </section>
        </div>
      </div>
    </div>
  </div>

  <script>
    const initialScanId = __INITIAL_SCAN_ID__;
    const viewerMode = "__VIEWER_MODE__";
    const embeddedData = __EMBEDDED_DATA__;
    let selectedBinaryId = null;
    let binariesRequestToken = 0;
    let detailsRequestToken = 0;
    let filterDebounceTimer = null;

    const scanSelect = document.getElementById("scan-select");
    const permissionSelect = document.getElementById("permission-select");
    const entitlementSelect = document.getElementById("entitlement-select");
    const pathInput = document.getElementById("path-input");
    const entitlementInput = document.getElementById("entitlement-input");
    const resultsBody = document.getElementById("results-body");
    const resultsCount = document.getElementById("results-count");
    const resultsNote = document.getElementById("results-note");
    const statusPill = document.getElementById("status-pill");
    const detailsModal = document.getElementById("details-modal");
    const modalCloseButton = document.getElementById("modal-close");
    const modalTitle = document.getElementById("modal-title");
    const modalSubtitle = document.getElementById("modal-subtitle");
    const metadataCard = document.getElementById("metadata-card");
    const entitlementsCard = document.getElementById("entitlements-card");
    const errorsCard = document.getElementById("errors-card");
    const metadataPanel = document.getElementById("metadata-panel");
    const entitlementsPanel = document.getElementById("entitlements-panel");
    const errorsPanel = document.getElementById("errors-panel");

    function setPanel(panel, text, emptyText) {
      panel.textContent = text || emptyText;
      panel.classList.toggle("empty", !text);
    }

    function setSectionVisible(section, isVisible) {
      section.classList.toggle("hidden", !isVisible);
    }

    function closeModal() {
      detailsModal.classList.remove("open");
      detailsModal.setAttribute("aria-hidden", "true");
    }

    function openModal() {
      detailsModal.classList.add("open");
      detailsModal.setAttribute("aria-hidden", "false");
    }

    function setStatusPill(message, tone = "neutral") {
      statusPill.textContent = message;
      statusPill.className = "status-pill";
      if (tone === "good") {
        statusPill.classList.add("status-good");
      } else if (tone === "warn") {
        statusPill.classList.add("status-warn");
      } else if (tone === "error") {
        statusPill.classList.add("status-error");
      }
    }

    function escapeHtml(value) {
      return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    }

    function parseOptionalInt(value) {
      if (value === null || value === undefined || value === "") {
        return null;
      }
      const parsed = Number.parseInt(String(value), 10);
      return Number.isNaN(parsed) ? null : parsed;
    }

    function parseModeBits(modeOctal) {
      const parsed = Number.parseInt(String(modeOctal || "0"), 8);
      return Number.isNaN(parsed) ? 0 : parsed;
    }

    function includesFolded(haystack, needle) {
      const search = String(needle || "").trim().toLocaleLowerCase();
      if (!search) {
        return true;
      }
      return String(haystack || "").toLocaleLowerCase().includes(search);
    }

    function matchesPermissionFilter(binary, filterName) {
      const modeBits = parseModeBits(binary.mode_octal);
      switch (filterName || "all") {
        case "all":
          return true;
        case "setuid":
          return (modeBits & 2048) !== 0;
        case "setgid":
          return (modeBits & 1024) !== 0;
        case "sticky":
          return (modeBits & 512) !== 0;
        case "group_writable":
          return (modeBits & 16) !== 0;
        case "world_writable":
          return (modeBits & 2) !== 0;
        default:
          throw new Error("unsupported permission filter: " + filterName);
      }
    }

    function matchesEntitlementFilter(binary, filterName) {
      const value = filterName || "all";
      switch (value) {
        case "all":
          return true;
        case "has_entitlements":
          return Boolean(binary.has_entitlements);
        case "no_entitlements":
          return !binary.has_entitlements;
        case "unsigned":
          return binary.entitlement_extraction_status === "unsigned";
        case "error":
          return binary.entitlement_extraction_status === "error";
        case "none":
          return binary.entitlement_extraction_status === "none";
        case "extracted":
          return binary.entitlement_extraction_status === "extracted";
        default:
          throw new Error("unsupported entitlement filter: " + filterName);
      }
    }

    function binaryMatchesFilters(binary, params) {
      const scanId = parseOptionalInt(params.get("scan_id"));
      if (scanId !== null && binary.scan_id !== scanId) {
        return false;
      }
      if (!includesFolded(binary.path, params.get("path_contains"))) {
        return false;
      }
      if (!matchesPermissionFilter(binary, params.get("permission_filter"))) {
        return false;
      }
      if (!matchesEntitlementFilter(binary, params.get("entitlement_filter"))) {
        return false;
      }
      if (!includesFolded(binary.entitlements_xml || "", params.get("entitlement_key_contains"))) {
        return false;
      }
      return true;
    }

    function binaryToListItem(binary) {
      return {
        binary_id: binary.binary_id,
        scan_id: binary.scan_id,
        path: binary.path,
        real_path: binary.real_path,
        mode_octal: binary.mode_octal,
        mode_symbolic: binary.mode_symbolic,
        uid: binary.uid,
        gid: binary.gid,
        has_entitlements: binary.has_entitlements,
        entitlement_extraction_status: binary.entitlement_extraction_status,
        is_universal: binary.is_universal,
      };
    }

    function staticApi(path) {
      const url = new URL(path, "http://mtm.local");
      if (url.pathname === "/api/scans") {
        return embeddedData && embeddedData.scans ? embeddedData.scans : [];
      }
      if (url.pathname === "/api/binaries") {
        const binaries = embeddedData && embeddedData.binaries ? embeddedData.binaries : [];
        const items = binaries.filter((binary) => binaryMatchesFilters(binary, url.searchParams)).map(binaryToListItem);
        return {
          total_matches: items.length,
          items,
        };
      }
      if (url.pathname.startsWith("/api/binary/")) {
        const binaryId = parseOptionalInt(url.pathname.split("/").pop());
        const binaries = embeddedData && embeddedData.binaries ? embeddedData.binaries : [];
        const details = binaries.find((binary) => binary.binary_id === binaryId);
        if (!details) {
          throw new Error("binary not found");
        }
        return details;
      }
      throw new Error("not found");
    }

    async function api(path) {
      if (viewerMode === "static") {
        return staticApi(path);
      }
      const response = await fetch(path);
      const body = await response.text();
      const parsed = body ? JSON.parse(body) : null;
      if (!response.ok) {
        throw new Error((parsed && parsed.error) || body || ("HTTP " + response.status));
      }
      return parsed;
    }

    function badgeClassForStatus(status) {
      const value = String(status || "").toLowerCase();
      if (value === "extracted") return "badge-good";
      if (value === "unsigned") return "badge-warn";
      if (value === "error") return "badge-error";
      if (value === "none") return "badge-muted";
      return "badge-neutral";
    }

    function renderBadge(label, className) {
      return `<span class="badge ${className}">${escapeHtml(label)}</span>`;
    }

    function renderBooleanBadge(value, positiveLabel, negativeLabel) {
      if (value) {
        return renderBadge(positiveLabel, "badge-good");
      }
      return renderBadge(negativeLabel, "badge-muted");
    }

    function formatScanLabel(scan) {
      return "#" + scan.scan_id + "  " + scan.status + "  " + scan.root_path + "  " +
        scan.total_binaries_identified + " binaries";
    }

    async function loadScans() {
      const scans = await api("/api/scans");
      scanSelect.innerHTML = "";
      if (!scans.length) {
        setStatusPill("No scans found in this database", "warn");
        resultsCount.textContent = "No scans available.";
        return;
      }
      scans.forEach((scan) => {
        const option = document.createElement("option");
        option.value = String(scan.scan_id);
        option.textContent = formatScanLabel(scan);
        if (initialScanId !== null && scan.scan_id === initialScanId) {
          option.selected = true;
        }
        scanSelect.appendChild(option);
      });
      if (!scanSelect.value) {
        scanSelect.selectedIndex = 0;
      }
      await loadBinaries();
    }

    function currentQuery() {
      const params = new URLSearchParams();
      if (scanSelect.value) params.set("scan_id", scanSelect.value);
      if (permissionSelect.value) params.set("permission_filter", permissionSelect.value);
      if (entitlementSelect.value) params.set("entitlement_filter", entitlementSelect.value);
      if (pathInput.value.trim()) params.set("path_contains", pathInput.value.trim());
      if (entitlementInput.value.trim()) params.set("entitlement_key_contains", entitlementInput.value.trim());
      return params.toString();
    }

    async function loadBinaries() {
      const requestToken = ++binariesRequestToken;
      setStatusPill("Loading binaries...");
      resultsBody.innerHTML = "";
      closeModal();

      const data = await api("/api/binaries?" + currentQuery());
      // Ignore out-of-order responses when reactive filters trigger overlapping fetches.
      if (requestToken !== binariesRequestToken) {
        return;
      }
      const items = data.items || [];
      resultsCount.textContent = "Loaded " + items.length + " of " + data.total_matches + " matching binaries";
      resultsNote.textContent = items.length
        ? "Click any row to inspect metadata, entitlements, and extraction errors."
        : "Try broadening the filters or choosing a different scan.";
      setStatusPill("Scan #" + scanSelect.value + " ready", items.length ? "good" : "warn");

      if (!items.length) {
        resultsBody.innerHTML = `
          <tr class="empty-row">
            <td colspan="6">
              <div class="empty-state">
                <strong>No binaries match the current filters.</strong>
                <span>Adjust the filters above or select a different scan to widen the search.</span>
              </div>
            </td>
          </tr>
        `;
        selectedBinaryId = null;
        return;
      }

      items.forEach((item) => {
        const row = document.createElement("tr");
        row.className = "result-row";
        row.dataset.binaryId = String(item.binary_id);
        const realPathHtml = item.real_path && item.real_path !== item.path
          ? `<div class="row-secondary mono">${escapeHtml(item.real_path)}</div>`
          : "";
        row.innerHTML = `
          <!-- data-label is used by the mobile card layout when the table collapses -->
          <td data-label="Path">
            <div class="row-path mono">${escapeHtml(item.path)}</div>
            ${realPathHtml}
          </td>
          <td class="mono" data-label="Mode">${escapeHtml(item.mode_octal)} ${escapeHtml(item.mode_symbolic)}</td>
          <td class="mono" data-label="UID:GID">${escapeHtml(item.uid)}:${escapeHtml(item.gid)}</td>
          <td data-label="Status">${renderBadge(item.entitlement_extraction_status, badgeClassForStatus(item.entitlement_extraction_status))}</td>
          <td data-label="Entitlements">${renderBooleanBadge(item.has_entitlements, "present", "none")}</td>
          <td data-label="Universal">${renderBooleanBadge(item.is_universal, "yes", "no")}</td>
        `;
        row.addEventListener("click", () => loadDetails(item.binary_id, row));
        resultsBody.appendChild(row);
      });

      if (items.length) {
        const selectedRow = selectedBinaryId === null
          ? null
          : resultsBody.querySelector(`[data-binary-id="${selectedBinaryId}"]`);
        if (selectedRow) {
          selectedRow.classList.add("selected");
        } else {
          selectedBinaryId = null;
        }
      } else {
        selectedBinaryId = null;
      }
    }

    async function loadDetails(binaryId, row) {
      const detailToken = ++detailsRequestToken;
      selectedBinaryId = binaryId;
      Array.from(resultsBody.querySelectorAll("tr")).forEach((entry) => entry.classList.remove("selected"));
      if (row) row.classList.add("selected");
      setStatusPill("Loading binary #" + binaryId + "...");
      const details = await api("/api/binary/" + binaryId);
      if (detailToken !== detailsRequestToken) {
        return;
      }
      const metadataLines = [
        "binary_id: " + details.binary_id,
        "scan_id: " + details.scan_id,
        "path: " + details.path,
        "real_path: " + details.real_path,
        "root_path: " + details.root_path,
        "file_type: " + details.file_type,
        "binary_reason: " + details.binary_reason,
        "is_macho: " + details.is_macho,
        "is_universal: " + details.is_universal,
        "mode_octal: " + details.mode_octal,
        "mode_symbolic: " + details.mode_symbolic,
        "uid: " + details.uid,
        "gid: " + details.gid,
        "size: " + details.size,
        "inode: " + details.inode,
        "device: " + details.device,
        "mtime: " + details.mtime,
        "ctime: " + details.ctime,
        "has_entitlements: " + details.has_entitlements,
        "entitlement_extraction_status: " + details.entitlement_extraction_status,
        "entitlement_extraction_error: " + details.entitlement_extraction_error,
        "discovered_at: " + details.discovered_at
      ];
      modalTitle.textContent = "Binary Details";
      modalSubtitle.textContent = details.path;
      setPanel(metadataPanel, metadataLines.join("\\n"), "Select a binary to inspect metadata.");
      setSectionVisible(metadataCard, true);

      const hasEntitlements = Boolean(details.entitlements_display_xml);
      setSectionVisible(entitlementsCard, hasEntitlements);
      setPanel(entitlementsPanel, details.entitlements_display_xml || "", "");

      const hasErrors = Boolean(details.error_text);
      setSectionVisible(errorsCard, hasErrors);
      setPanel(errorsPanel, details.error_text || "", "");

      openModal();
      setStatusPill("Binary: " + details.path, "good");
    }

    function resetFilters() {
      permissionSelect.value = "all";
      entitlementSelect.value = "all";
      pathInput.value = "";
      entitlementInput.value = "";
      scheduleFilterApply(0);
    }

    function scheduleFilterApply(delayMs = 250) {
      window.clearTimeout(filterDebounceTimer);
      filterDebounceTimer = window.setTimeout(() => {
        loadBinaries().catch(showError);
      }, delayMs);
    }

    function showError(error) {
      const message = error && error.message ? error.message : String(error);
      setStatusPill("Viewer error", "error");
      resultsCount.innerHTML = `<span class="warning">${message}</span>`;
    }

    document.getElementById("apply-button").addEventListener("click", () => loadBinaries().catch(showError));
    document.getElementById("reset-button").addEventListener("click", resetFilters);
    modalCloseButton.addEventListener("click", closeModal);
    detailsModal.addEventListener("click", (event) => {
      if (event.target === detailsModal) {
        closeModal();
      }
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        closeModal();
      }
    });
    [scanSelect, permissionSelect, entitlementSelect].forEach((element) => {
      element.addEventListener("change", () => scheduleFilterApply(0));
    });
    [pathInput, entitlementInput].forEach((element) => {
      element.addEventListener("input", () => scheduleFilterApply(250));
      element.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          window.clearTimeout(filterDebounceTimer);
          loadBinaries().catch(showError);
        }
      });
    });

    loadScans().catch(showError);
  </script>
</body>
</html>
"""
