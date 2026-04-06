"""SQLite persistence layer."""

from __future__ import annotations

import csv
import json
from pathlib import Path
import sqlite3
from typing import Iterable

from mtm.models import BinaryRecord, ScanConfig, ScanCounters, ScanErrorRecord, ScanSession, ScanStatus


class Database:
    """Wrapper around a SQLite database used by the scanner."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(path))
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA synchronous = NORMAL")
        self.connection.execute("PRAGMA temp_store = MEMORY")
        self._create_schema()

    def close(self) -> None:
        """Close the underlying SQLite connection."""

        self.connection.close()

    def commit(self) -> None:
        """Commit pending changes."""

        self.connection.commit()

    def rollback(self) -> None:
        """Rollback pending changes."""

        self.connection.rollback()

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                hostname TEXT NOT NULL,
                macos_version TEXT NOT NULL,
                tool_version TEXT NOT NULL,
                effective_uid INTEGER NOT NULL,
                root_path TEXT NOT NULL,
                follow_symlinks INTEGER NOT NULL,
                exclude_prefixes_json TEXT NOT NULL,
                workers INTEGER NOT NULL,
                resume_requested INTEGER NOT NULL,
                status TEXT NOT NULL,
                total_files_visited INTEGER NOT NULL DEFAULT 0,
                total_binaries_identified INTEGER NOT NULL DEFAULT 0,
                total_extraction_failures INTEGER NOT NULL DEFAULT 0,
                total_errors INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS binaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                path TEXT NOT NULL,
                real_path TEXT NOT NULL,
                root_path TEXT NOT NULL,
                file_type TEXT NOT NULL,
                binary_reason TEXT NOT NULL,
                is_macho INTEGER NOT NULL,
                is_universal INTEGER NOT NULL,
                mode_octal TEXT NOT NULL,
                mode_bits INTEGER NOT NULL,
                mode_symbolic TEXT NOT NULL,
                uid INTEGER NOT NULL,
                gid INTEGER NOT NULL,
                size INTEGER NOT NULL,
                inode INTEGER NOT NULL,
                device INTEGER NOT NULL,
                mtime REAL NOT NULL,
                ctime REAL NOT NULL,
                has_entitlements INTEGER NOT NULL,
                entitlement_extraction_status TEXT NOT NULL,
                entitlement_extraction_error TEXT,
                discovered_at TEXT NOT NULL,
                UNIQUE(scan_id, device, inode)
            );

            CREATE TABLE IF NOT EXISTS entitlements (
                binary_id INTEGER PRIMARY KEY REFERENCES binaries(id) ON DELETE CASCADE,
                entitlements_xml TEXT NOT NULL,
                extracted_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS errors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                binary_id INTEGER REFERENCES binaries(id) ON DELETE SET NULL,
                path TEXT,
                stage TEXT NOT NULL,
                error_type TEXT NOT NULL,
                message TEXT NOT NULL,
                stderr TEXT,
                errno INTEGER,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scans_root_status
                ON scans(root_path, status);

            CREATE INDEX IF NOT EXISTS idx_binaries_path
                ON binaries(path);

            CREATE INDEX IF NOT EXISTS idx_binaries_real_path
                ON binaries(real_path);

            CREATE INDEX IF NOT EXISTS idx_binaries_status
                ON binaries(entitlement_extraction_status);

            CREATE INDEX IF NOT EXISTS idx_binaries_has_entitlements
                ON binaries(has_entitlements);

            CREATE INDEX IF NOT EXISTS idx_binaries_scan_status
                ON binaries(scan_id, entitlement_extraction_status);

            CREATE INDEX IF NOT EXISTS idx_errors_scan_stage
                ON errors(scan_id, stage);
            """
        )
        self.commit()

    def start_or_resume_scan(
        self,
        config: ScanConfig,
        *,
        started_at: str,
        hostname: str,
        macos_version: str,
        tool_version: str,
        effective_uid: int,
    ) -> ScanSession:
        """Start a new scan or resume the latest unfinished one for the same root."""

        if config.resume:
            row = self.connection.execute(
                """
                SELECT *
                FROM scans
                WHERE root_path = ? AND status = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (str(config.root_path), ScanStatus.RUNNING.value),
            ).fetchone()
            if row is not None:
                return ScanSession(
                    scan_id=row["id"],
                    resumed=True,
                    prior_counters=ScanCounters(
                        files_visited=row["total_files_visited"],
                        binaries_identified=row["total_binaries_identified"],
                        extraction_failures=row["total_extraction_failures"],
                        errors=row["total_errors"],
                    ),
                )

        cursor = self.connection.execute(
            """
            INSERT INTO scans (
                started_at,
                hostname,
                macos_version,
                tool_version,
                effective_uid,
                root_path,
                follow_symlinks,
                exclude_prefixes_json,
                workers,
                resume_requested,
                status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                started_at,
                hostname,
                macos_version,
                tool_version,
                effective_uid,
                str(config.root_path),
                int(config.follow_symlinks),
                json.dumps([str(prefix) for prefix in config.exclude_prefixes]),
                config.workers,
                int(config.resume),
                ScanStatus.RUNNING.value,
            ),
        )
        self.commit()
        return ScanSession(scan_id=int(cursor.lastrowid), resumed=False)

    def load_completed_file_keys(self, scan_id: int) -> set[tuple[int, int]]:
        """Load previously inserted device/inode pairs for resuming scans."""

        rows = self.connection.execute(
            "SELECT device, inode FROM binaries WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()
        return {(int(row["device"]), int(row["inode"])) for row in rows}

    def insert_binary_with_errors(
        self,
        record: BinaryRecord,
        errors: Iterable[ScanErrorRecord],
    ) -> bool:
        """Insert a binary record, its entitlement blob, and any related errors."""

        self.connection.execute("SAVEPOINT insert_binary")
        try:
            cursor = self.connection.execute(
                """
                INSERT OR IGNORE INTO binaries (
                    scan_id,
                    path,
                    real_path,
                    root_path,
                    file_type,
                    binary_reason,
                    is_macho,
                    is_universal,
                    mode_octal,
                    mode_bits,
                    mode_symbolic,
                    uid,
                    gid,
                    size,
                    inode,
                    device,
                    mtime,
                    ctime,
                    has_entitlements,
                    entitlement_extraction_status,
                    entitlement_extraction_error,
                    discovered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.scan_id,
                    record.path,
                    record.real_path,
                    record.root_path,
                    record.file_type,
                    record.binary_reason,
                    int(record.is_macho),
                    int(record.is_universal),
                    record.mode_octal,
                    record.mode_bits,
                    record.mode_symbolic,
                    record.uid,
                    record.gid,
                    record.size,
                    record.inode,
                    record.device,
                    record.mtime,
                    record.ctime,
                    int(record.has_entitlements),
                    record.entitlement_extraction_status,
                    record.entitlement_extraction_error,
                    record.discovered_at,
                ),
            )
            if cursor.rowcount == 0:
                self.connection.execute("ROLLBACK TO SAVEPOINT insert_binary")
                self.connection.execute("RELEASE SAVEPOINT insert_binary")
                return False

            binary_id = int(cursor.lastrowid)
            if record.entitlements_xml is not None:
                self.connection.execute(
                    """
                    INSERT INTO entitlements (binary_id, entitlements_xml, extracted_at)
                    VALUES (?, ?, ?)
                    """,
                    (binary_id, record.entitlements_xml, record.discovered_at),
                )

            for error in errors:
                self.connection.execute(
                    """
                    INSERT INTO errors (
                        scan_id,
                        binary_id,
                        path,
                        stage,
                        error_type,
                        message,
                        stderr,
                        errno,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        error.scan_id,
                        binary_id,
                        error.path,
                        error.stage,
                        error.error_type,
                        error.message,
                        error.stderr,
                        error.errno,
                        error.created_at,
                    ),
                )
            self.connection.execute("RELEASE SAVEPOINT insert_binary")
            return True
        except Exception:
            self.connection.execute("ROLLBACK TO SAVEPOINT insert_binary")
            self.connection.execute("RELEASE SAVEPOINT insert_binary")
            raise

    def insert_errors(self, errors: Iterable[ScanErrorRecord]) -> int:
        """Insert standalone error records."""

        rows = [
            (
                error.scan_id,
                error.binary_id,
                error.path,
                error.stage,
                error.error_type,
                error.message,
                error.stderr,
                error.errno,
                error.created_at,
            )
            for error in errors
        ]
        if not rows:
            return 0
        self.connection.executemany(
            """
            INSERT INTO errors (
                scan_id,
                binary_id,
                path,
                stage,
                error_type,
                message,
                stderr,
                errno,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        return len(rows)

    def update_scan_progress(self, scan_id: int, counters: ScanCounters) -> None:
        """Persist the latest counters while the scan is still running."""

        self.connection.execute(
            """
            UPDATE scans
            SET total_files_visited = ?,
                total_binaries_identified = ?,
                total_extraction_failures = ?,
                total_errors = ?
            WHERE id = ?
            """,
            (
                counters.files_visited,
                counters.binaries_identified,
                counters.extraction_failures,
                counters.errors,
                scan_id,
            ),
        )

    def finalize_scan(
        self,
        scan_id: int,
        *,
        ended_at: str,
        status: ScanStatus,
        counters: ScanCounters,
    ) -> None:
        """Mark a scan as completed or failed."""

        self.connection.execute(
            """
            UPDATE scans
            SET ended_at = ?,
                status = ?,
                total_files_visited = ?,
                total_binaries_identified = ?,
                total_extraction_failures = ?,
                total_errors = ?
            WHERE id = ?
            """,
            (
                ended_at,
                status.value,
                counters.files_visited,
                counters.binaries_identified,
                counters.extraction_failures,
                counters.errors,
                scan_id,
            ),
        )
        self.commit()

    def export_scan_to_csv(self, scan_id: int, csv_path: Path) -> None:
        """Export a flattened view of the scan results to CSV."""

        csv_path.parent.mkdir(parents=True, exist_ok=True)
        cursor = self.connection.execute(
            """
            SELECT
                b.id,
                b.scan_id,
                b.path,
                b.real_path,
                b.root_path,
                b.file_type,
                b.binary_reason,
                b.is_macho,
                b.is_universal,
                b.mode_octal,
                b.mode_bits,
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
            WHERE b.scan_id = ?
            ORDER BY b.path
            """,
            (scan_id,),
        )

        fieldnames = [column[0] for column in cursor.description]
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in cursor:
                writer.writerow(dict(row))
