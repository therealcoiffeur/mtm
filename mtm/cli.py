"""Command-line entry point."""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path
import platform
import shutil
import sys

from mtm import __version__
from mtm.gui import export_static_html, launch_gui
from mtm.logging_utils import configure_logging
from mtm.models import ScanConfig
from mtm.scanner import run_scan

LOGGER = logging.getLogger("mtm.cli")


def build_parser() -> argparse.ArgumentParser:
    """Build the MTM CLI parser."""

    parser = argparse.ArgumentParser(
        prog="mtm",
        description="Map local macOS Mach-O binaries and browse results in SQLite.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser(
        "scan",
        help="Run a filesystem scan and store the results in SQLite.",
    )
    _add_scan_arguments(scan_parser)

    gui_parser = subparsers.add_parser(
        "gui",
        help="Open the local browser viewer for an MTM SQLite database.",
    )
    gui_parser.add_argument(
        "--db",
        default="mtm_scan.sqlite3",
        help="SQLite database path to open in the viewer.",
    )
    gui_parser.add_argument(
        "--scan-id",
        type=int,
        help="Optional scan ID to preselect in the viewer.",
    )
    gui_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )

    export_html_parser = subparsers.add_parser(
        "export-html",
        help="Write a self-contained browser viewer with embedded JSON data.",
    )
    export_html_parser.add_argument(
        "--db",
        default="mtm_scan.sqlite3",
        help="SQLite database path to export from.",
    )
    export_html_parser.add_argument(
        "--output",
        default="mtm_viewer.html",
        help="Output HTML path for the self-contained viewer.",
    )
    export_html_parser.add_argument(
        "--scan-id",
        type=int,
        help="Optional scan ID to preselect when the static viewer opens.",
    )
    export_html_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI."""

    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(_normalize_argv(raw_argv))
    configure_logging(getattr(args, "verbose", False))

    try:
        if args.command == "gui":
            return _run_gui(args)
        if args.command == "export-html":
            return _run_export_html(args)

        config = _build_scan_config(args)
        _validate_scan_runtime(config)
        summary = run_scan(config)
    except ValueError as exc:
        LOGGER.error("%s", exc)
        return 2
    except RuntimeError as exc:
        LOGGER.error("%s", exc)
        return 2
    except KeyboardInterrupt:
        LOGGER.error("operation interrupted by user")
        return 130

    print(
        "scan_id={scan_id} resumed={resumed} db={db} files_visited={files} "
        "binaries={binaries} extraction_failures={failures} errors={errors}".format(
            scan_id=summary.scan_id,
            resumed=str(summary.resumed).lower(),
            db=summary.db_path,
            files=summary.counters.files_visited,
            binaries=summary.counters.binaries_identified,
            failures=summary.counters.extraction_failures,
            errors=summary.counters.errors,
        )
    )
    return 0


def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    """Add scan-mode arguments to a parser."""

    parser.add_argument(
        "--root",
        default="/",
        help="Filesystem root to scan. Defaults to /.",
    )
    parser.add_argument(
        "--db",
        default="mtm_scan.sqlite3",
        help="SQLite database output path. Defaults to ./mtm_scan.sqlite3.",
    )
    parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Follow symlinked directories and files during traversal.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude a path prefix. Repeat the flag to add multiple prefixes.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume the latest unfinished scan for the same root path and database.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=_default_workers(),
        help="Number of concurrent worker threads for classification and entitlement extraction.",
    )
    parser.add_argument(
        "--export-csv",
        help="Optional CSV output path for a flattened export after the scan completes.",
    )
    parser.add_argument(
        "--include-special-files",
        action="store_true",
        help="Also inspect non-regular files encountered during traversal.",
    )


def _build_scan_config(args: argparse.Namespace) -> ScanConfig:
    """Translate parsed CLI arguments into a validated config object."""

    root_path = Path(args.root).expanduser().resolve(strict=False)
    db_path = Path(args.db).expanduser().resolve(strict=False)
    exclude_prefixes = tuple(
        Path(prefix).expanduser().resolve(strict=False) for prefix in args.exclude
    )
    export_csv = Path(args.export_csv).expanduser().resolve(strict=False) if args.export_csv else None
    if args.workers < 1:
        raise ValueError("--workers must be at least 1")

    return ScanConfig(
        root_path=root_path,
        db_path=db_path,
        follow_symlinks=args.follow_symlinks,
        verbose=args.verbose,
        exclude_prefixes=exclude_prefixes,
        resume=args.resume,
        workers=args.workers,
        export_csv=export_csv,
        include_special_files=args.include_special_files,
    )


def _validate_scan_runtime(config: ScanConfig) -> None:
    """Validate runtime assumptions before scanning."""

    if platform.system() != "Darwin":
        raise RuntimeError("mtm only supports macOS (Darwin)")
    if os.geteuid() != 0:
        raise RuntimeError("mtm must run as root; effective UID is not 0")
    if not config.root_path.exists():
        raise ValueError(f"scan root does not exist: {config.root_path}")
    if not config.root_path.is_dir():
        raise ValueError(f"scan root must be a directory: {config.root_path}")
    if shutil.which("codesign") is None:
        raise RuntimeError("codesign was not found in PATH; entitlement extraction cannot proceed")
    if config.export_csv is not None and config.export_csv == config.db_path:
        raise ValueError("--export-csv must point to a different file than --db")


def _run_gui(args: argparse.Namespace) -> int:
    """Run the local database viewer."""

    db_path = Path(args.db).expanduser().resolve(strict=False)
    if not db_path.exists():
        raise ValueError(f"database not found: {db_path}")
    return launch_gui(db_path, initial_scan_id=args.scan_id)


def _run_export_html(args: argparse.Namespace) -> int:
    """Write a standalone HTML viewer with embedded data."""

    db_path = Path(args.db).expanduser().resolve(strict=False)
    output_path = Path(args.output).expanduser().resolve(strict=False)
    if not db_path.exists():
        raise ValueError(f"database not found: {db_path}")
    if output_path == db_path:
        raise ValueError("--output must point to a different file than --db")
    written_path = export_static_html(
        db_path,
        output_path,
        initial_scan_id=args.scan_id,
    )
    print(f"wrote static viewer to {written_path}")
    return 0


def _normalize_argv(argv: list[str]) -> list[str]:
    """Preserve legacy scan invocations while supporting subcommands."""

    if not argv:
        return ["scan"]
    if argv[0] in {"scan", "gui", "export-html", "-h", "--help", "--version"}:
        return argv
    return ["scan", *argv]


def _default_workers() -> int:
    """Return a conservative worker default."""

    cpu_count = os.cpu_count() or 2
    return max(1, min(4, cpu_count))


if __name__ == "__main__":
    sys.exit(main())
