"""Shared data models for the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ScanStatus(str, Enum):
    """Lifecycle states for a scan record."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class EntitlementStatus(str, Enum):
    """Status of entitlement extraction for a binary."""

    EXTRACTED = "extracted"
    NONE = "none"
    UNSIGNED = "unsigned"
    ERROR = "error"


@dataclass(frozen=True)
class ScanConfig:
    """Runtime configuration for a filesystem scan."""

    root_path: Path
    db_path: Path
    follow_symlinks: bool = False
    verbose: bool = False
    exclude_prefixes: tuple[Path, ...] = ()
    resume: bool = False
    workers: int = 4
    export_csv: Path | None = None
    include_special_files: bool = False
    progress_interval_seconds: int = 30


@dataclass(frozen=True)
class BinaryClassification:
    """Classification details for a candidate binary file."""

    is_macho: bool
    is_universal: bool
    reason: str


@dataclass(frozen=True)
class ExtractionResult:
    """Result returned by the entitlement extraction layer."""

    status: EntitlementStatus
    has_entitlements: bool
    entitlements_xml: str | None
    error_message: str | None
    stderr: str | None


@dataclass(frozen=True)
class BinaryRecord:
    """Normalized binary record ready for insertion into SQLite."""

    scan_id: int
    path: str
    real_path: str
    root_path: str
    file_type: str
    binary_reason: str
    is_macho: bool
    is_universal: bool
    mode_octal: str
    mode_bits: int
    mode_symbolic: str
    uid: int
    gid: int
    size: int
    inode: int
    device: int
    mtime: float
    ctime: float
    has_entitlements: bool
    entitlement_extraction_status: str
    entitlement_extraction_error: str | None
    discovered_at: str
    entitlements_xml: str | None = None


@dataclass(frozen=True)
class ScanErrorRecord:
    """Structured error record for operational failures."""

    scan_id: int
    path: str | None
    stage: str
    error_type: str
    message: str
    stderr: str | None
    errno: int | None
    created_at: str
    binary_id: int | None = None


@dataclass(frozen=True)
class ProcessingResult:
    """Outcome of worker-side file processing."""

    binary: BinaryRecord | None = None
    errors: tuple[ScanErrorRecord, ...] = ()


@dataclass
class ScanCounters:
    """Mutable counters tracked during a scan."""

    files_visited: int = 0
    binaries_identified: int = 0
    extraction_failures: int = 0
    errors: int = 0

    def as_dict(self) -> dict[str, int]:
        """Return the counters as a plain dictionary."""

        return {
            "files_visited": self.files_visited,
            "binaries_identified": self.binaries_identified,
            "extraction_failures": self.extraction_failures,
            "errors": self.errors,
        }


@dataclass(frozen=True)
class ScanSession:
    """Information about the active or resumed scan session."""

    scan_id: int
    resumed: bool
    prior_counters: ScanCounters = field(default_factory=ScanCounters)


@dataclass(frozen=True)
class ViewerScanSummary:
    """Compact scan metadata used by the GUI."""

    scan_id: int
    started_at: str
    ended_at: str | None
    root_path: str
    status: str
    total_binaries_identified: int
    total_extraction_failures: int


@dataclass(frozen=True)
class BinaryFilter:
    """User-selected filters for browsing binaries."""

    scan_id: int | None = None
    path_contains: str = ""
    permission_filter: str = "all"
    entitlement_filter: str = "all"
    entitlement_key_contains: str = ""


@dataclass(frozen=True)
class BinaryListItem:
    """Flattened binary row shown in the GUI table."""

    binary_id: int
    scan_id: int
    path: str
    real_path: str
    mode_octal: str
    mode_symbolic: str
    uid: int
    gid: int
    has_entitlements: bool
    entitlement_extraction_status: str
    is_universal: bool


@dataclass(frozen=True)
class BinaryDetails:
    """Detailed data for the currently selected binary."""

    binary_id: int
    scan_id: int
    path: str
    real_path: str
    root_path: str
    file_type: str
    binary_reason: str
    is_macho: bool
    is_universal: bool
    mode_octal: str
    mode_symbolic: str
    uid: int
    gid: int
    size: int
    inode: int
    device: int
    mtime: float
    ctime: float
    has_entitlements: bool
    entitlement_extraction_status: str
    entitlement_extraction_error: str | None
    discovered_at: str
    entitlements_xml: str | None
    entitlements_display_xml: str | None
    error_text: str
