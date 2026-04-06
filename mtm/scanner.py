"""Filesystem scanner implementation."""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import platform
import socket
import stat
import time
from typing import Iterator

from mtm import __version__
from mtm.binary_detection import classify_file
from mtm.database import Database
from mtm.entitlements import extract_entitlements
from mtm.models import (
    BinaryRecord,
    EntitlementStatus,
    ProcessingResult,
    ScanConfig,
    ScanCounters,
    ScanErrorRecord,
    ScanStatus,
)

LOGGER = logging.getLogger("mtm.scanner")
_COMMIT_EVERY_RESULTS = 100


@dataclass(frozen=True)
class ScanSummary:
    """High-level summary returned to the CLI."""

    scan_id: int
    resumed: bool
    db_path: Path
    counters: ScanCounters


def run_scan(config: ScanConfig) -> ScanSummary:
    """Run a full scan and return a summary."""

    database = Database(config.db_path)
    started_at = _utc_now()
    hostname = socket.gethostname()
    macos_version = _macos_version_string()
    effective_uid = os.geteuid()
    session = database.start_or_resume_scan(
        config,
        started_at=started_at,
        hostname=hostname,
        macos_version=macos_version,
        tool_version=__version__,
        effective_uid=effective_uid,
    )
    counters = ScanCounters(
        files_visited=session.prior_counters.files_visited,
        binaries_identified=session.prior_counters.binaries_identified,
        extraction_failures=session.prior_counters.extraction_failures,
        errors=session.prior_counters.errors,
    )
    resumed_keys = database.load_completed_file_keys(session.scan_id) if session.resumed else set()
    pending: set[Future[ProcessingResult]] = set()
    pending_limit = max(32, config.workers * 8)
    processed_results_since_commit = 0
    last_progress_log = time.monotonic()

    LOGGER.info(
        "scan starting scan_id=%s root=%s workers=%s resume=%s",
        session.scan_id,
        config.root_path,
        config.workers,
        session.resumed,
    )

    try:
        with ThreadPoolExecutor(max_workers=config.workers, thread_name_prefix="mtm") as executor:
            for candidate_path in _walk_filesystem(
                config.root_path,
                follow_symlinks=config.follow_symlinks,
                exclude_prefixes=config.exclude_prefixes,
                include_special_files=config.include_special_files,
                scan_id=session.scan_id,
                counters=counters,
                database=database,
            ):
                pending.add(
                    executor.submit(
                        _process_candidate,
                        candidate_path,
                        session.scan_id,
                        str(config.root_path),
                        config.follow_symlinks,
                        resumed_keys,
                    )
                )
                if len(pending) >= pending_limit:
                    processed_results_since_commit += _drain_futures(
                        pending,
                        database,
                        counters,
                        return_when=FIRST_COMPLETED,
                    )
                processed_results_since_commit, last_progress_log = _maybe_report_progress(
                    database,
                    session.scan_id,
                    counters,
                    processed_results_since_commit,
                    last_progress_log,
                    config.progress_interval_seconds,
                )

            while pending:
                processed_results_since_commit += _drain_futures(
                    pending,
                    database,
                    counters,
                    return_when=FIRST_COMPLETED,
                )
                processed_results_since_commit, last_progress_log = _maybe_report_progress(
                    database,
                    session.scan_id,
                    counters,
                    processed_results_since_commit,
                    last_progress_log,
                    config.progress_interval_seconds,
                )

        if processed_results_since_commit:
            database.update_scan_progress(session.scan_id, counters)
            database.commit()
        database.finalize_scan(
            session.scan_id,
            ended_at=_utc_now(),
            status=ScanStatus.COMPLETED,
            counters=counters,
        )
        if config.export_csv is not None:
            database.export_scan_to_csv(session.scan_id, config.export_csv)
            LOGGER.info("csv export written path=%s", config.export_csv)
        return ScanSummary(
            scan_id=session.scan_id,
            resumed=session.resumed,
            db_path=config.db_path,
            counters=counters,
        )
    except Exception:
        database.rollback()
        database.finalize_scan(
            session.scan_id,
            ended_at=_utc_now(),
            status=ScanStatus.FAILED,
            counters=counters,
        )
        raise
    finally:
        database.close()


def _walk_filesystem(
    root_path: Path,
    *,
    follow_symlinks: bool,
    exclude_prefixes: tuple[Path, ...],
    include_special_files: bool,
    scan_id: int,
    counters: ScanCounters,
    database: Database,
) -> Iterator[Path]:
    """Yield candidate file paths while handling directory traversal errors."""

    stack = [root_path]
    visited_directories: set[tuple[int, int]] = set()
    if follow_symlinks:
        try:
            stat_result = root_path.stat()
            visited_directories.add((stat_result.st_dev, stat_result.st_ino))
        except OSError:
            pass

    while stack:
        current = stack.pop()
        if _is_excluded(current, exclude_prefixes):
            continue
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    if _is_excluded(path, exclude_prefixes):
                        continue
                    try:
                        if entry.is_dir(follow_symlinks=follow_symlinks):
                            if follow_symlinks:
                                try:
                                    dir_stat = entry.stat(follow_symlinks=True)
                                except OSError as exc:
                                    _record_walk_error(database, counters, scan_id, path, "walk-dir-stat", exc)
                                    continue
                                dir_key = (dir_stat.st_dev, dir_stat.st_ino)
                                if dir_key in visited_directories:
                                    continue
                                visited_directories.add(dir_key)
                            stack.append(path)
                            continue

                        if entry.is_file(follow_symlinks=follow_symlinks):
                            counters.files_visited += 1
                            yield path
                            continue

                        if include_special_files:
                            counters.files_visited += 1
                            yield path
                    except OSError as exc:
                        _record_walk_error(database, counters, scan_id, path, "walk-entry", exc)
        except OSError as exc:
            _record_walk_error(database, counters, scan_id, current, "walk-scandir", exc)


def _process_candidate(
    path: Path,
    scan_id: int,
    root_path: str,
    follow_symlinks: bool,
    resumed_keys: set[tuple[int, int]],
) -> ProcessingResult:
    """Inspect a single file and return a binary record when applicable."""

    created_at = _utc_now()
    absolute_path = _safe_absolute(path)
    try:
        lstat_result = path.lstat()
    except OSError as exc:
        return ProcessingResult(
            errors=(
                _make_error(
                    scan_id,
                    absolute_path,
                    "lstat",
                    exc,
                    created_at=created_at,
                ),
            )
        )

    try:
        stat_result = path.stat()
    except OSError as exc:
        return ProcessingResult(
            errors=(
                _make_error(
                    scan_id,
                    absolute_path,
                    "stat",
                    exc,
                    created_at=created_at,
                ),
            )
        )

    if not stat.S_ISREG(stat_result.st_mode):
        return ProcessingResult()

    file_key = (stat_result.st_dev, stat_result.st_ino)
    if file_key in resumed_keys:
        return ProcessingResult()

    try:
        classification = classify_file(path, file_size=stat_result.st_size)
    except OSError as exc:
        return ProcessingResult(
            errors=(
                _make_error(
                    scan_id,
                    absolute_path,
                    "classify",
                    exc,
                    created_at=created_at,
                ),
            )
        )

    if not classification.is_macho:
        return ProcessingResult()

    real_path = _safe_realpath(path)
    extraction = extract_entitlements(Path(real_path))

    extraction_errors: list[ScanErrorRecord] = []
    if extraction.status in {EntitlementStatus.UNSIGNED, EntitlementStatus.ERROR}:
        extraction_errors.append(
            ScanErrorRecord(
                scan_id=scan_id,
                path=absolute_path,
                stage="entitlements",
                error_type=extraction.status.value,
                message=extraction.error_message or extraction.status.value,
                stderr=extraction.stderr,
                errno=None,
                created_at=created_at,
            )
        )

    record = BinaryRecord(
        scan_id=scan_id,
        path=absolute_path,
        real_path=real_path,
        root_path=root_path,
        file_type=_file_type_from_mode(lstat_result.st_mode, follow_symlinks),
        binary_reason=classification.reason,
        is_macho=classification.is_macho,
        is_universal=classification.is_universal,
        mode_octal=_mode_to_octal(stat_result.st_mode),
        mode_bits=stat.S_IMODE(stat_result.st_mode),
        mode_symbolic=stat.filemode(stat_result.st_mode),
        uid=stat_result.st_uid,
        gid=stat_result.st_gid,
        size=stat_result.st_size,
        inode=stat_result.st_ino,
        device=stat_result.st_dev,
        mtime=stat_result.st_mtime,
        ctime=stat_result.st_ctime,
        has_entitlements=extraction.has_entitlements,
        entitlement_extraction_status=extraction.status.value,
        entitlement_extraction_error=extraction.error_message,
        discovered_at=created_at,
        entitlements_xml=extraction.entitlements_xml,
    )
    return ProcessingResult(binary=record, errors=tuple(extraction_errors))


def _drain_futures(
    pending: set[Future[ProcessingResult]],
    database: Database,
    counters: ScanCounters,
    *,
    return_when: str,
) -> int:
    """Drain ready futures and persist their outputs."""

    if not pending:
        return 0

    completed, _ = wait(pending, return_when=return_when)
    processed = 0
    for future in completed:
        pending.remove(future)
        result = future.result()
        if result.binary is not None:
            inserted = database.insert_binary_with_errors(result.binary, result.errors)
            if inserted:
                counters.binaries_identified += 1
                if result.binary.entitlement_extraction_status in {
                    EntitlementStatus.UNSIGNED.value,
                    EntitlementStatus.ERROR.value,
                }:
                    counters.extraction_failures += 1
                    counters.errors += len(result.errors)
                processed += 1
            continue

        inserted_errors = database.insert_errors(result.errors)
        counters.errors += inserted_errors
        processed += 1
    return processed


def _maybe_report_progress(
    database: Database,
    scan_id: int,
    counters: ScanCounters,
    processed_results_since_commit: int,
    last_progress_log: float,
    interval_seconds: int,
) -> tuple[int, float]:
    """Periodically log progress and checkpoint the scan row."""

    now = time.monotonic()
    if processed_results_since_commit < _COMMIT_EVERY_RESULTS and (now - last_progress_log) < interval_seconds:
        return processed_results_since_commit, last_progress_log

    database.update_scan_progress(scan_id, counters)
    database.commit()
    LOGGER.info(
        "scan progress scan_id=%s files_visited=%s binaries=%s extraction_failures=%s errors=%s",
        scan_id,
        counters.files_visited,
        counters.binaries_identified,
        counters.extraction_failures,
        counters.errors,
    )
    return 0, now


def _record_walk_error(
    database: Database,
    counters: ScanCounters,
    scan_id: int,
    path: Path,
    stage: str,
    exc: OSError,
) -> None:
    """Persist traversal errors immediately."""

    record = _make_error(
        scan_id,
        _safe_absolute(path),
        stage,
        exc,
        created_at=_utc_now(),
    )
    counters.errors += database.insert_errors((record,))


def _make_error(
    scan_id: int,
    path: str,
    stage: str,
    exc: BaseException,
    *,
    created_at: str,
) -> ScanErrorRecord:
    """Create a structured error record from an exception."""

    return ScanErrorRecord(
        scan_id=scan_id,
        path=path,
        stage=stage,
        error_type=exc.__class__.__name__,
        message=str(exc),
        stderr=None,
        errno=getattr(exc, "errno", None),
        created_at=created_at,
    )


def _file_type_from_mode(mode: int, followed_symlink: bool) -> str:
    """Return a stable file type label."""

    if stat.S_ISLNK(mode):
        return "symlink" if followed_symlink else "symlink"
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISCHR(mode):
        return "character-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    return "unknown"


def _mode_to_octal(mode: int) -> str:
    """Render file mode bits as a four-digit octal string."""

    return format(stat.S_IMODE(mode), "04o")


def _safe_absolute(path: Path) -> str:
    """Return an absolute path string without resolving symlinks."""

    return os.path.abspath(os.fspath(path))


def _safe_realpath(path: Path) -> str:
    """Return a canonical path string, falling back to absolute form on error."""

    try:
        return str(path.resolve(strict=False))
    except Exception:
        return _safe_absolute(path)


def _is_excluded(path: Path, exclude_prefixes: tuple[Path, ...]) -> bool:
    """Return ``True`` if the path falls under an excluded prefix."""

    if not exclude_prefixes:
        return False

    try:
        absolute = Path(_safe_absolute(path))
    except Exception:
        return False

    for prefix in exclude_prefixes:
        try:
            absolute.relative_to(prefix)
            return True
        except ValueError:
            continue
    return False


def _utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""

    return datetime.now(timezone.utc).isoformat()


def _macos_version_string() -> str:
    """Return a human-readable macOS version string."""

    macos_version = platform.mac_ver()[0] or "unknown"
    darwin_version = os.uname().release
    machine = os.uname().machine
    return f"macOS {macos_version}; Darwin {darwin_version}; {machine}"
