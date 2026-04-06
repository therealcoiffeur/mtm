"""macOS code-signing entitlement extraction."""

from __future__ import annotations

from pathlib import Path
import plistlib
import subprocess

from mtm.models import EntitlementStatus, ExtractionResult

_CODESIGN = "/usr/bin/codesign"
_UNSIGNED_MARKERS = (
    "code object is not signed at all",
    "not signed at all",
    "code has no resources but signature indicates they must be present",
)


def extract_entitlements(path: Path, timeout_seconds: int = 30) -> ExtractionResult:
    """Extract entitlements from a Mach-O binary using ``codesign``."""

    try:
        completed = subprocess.run(
            [_CODESIGN, "-d", "--entitlements", ":-", str(path)],
            capture_output=True,
            check=False,
            text=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        message = f"codesign timed out after {timeout_seconds}s"
        stderr = _decode_bytes(exc.stderr)
        return ExtractionResult(
            status=EntitlementStatus.ERROR,
            has_entitlements=False,
            entitlements_xml=None,
            error_message=message,
            stderr=stderr,
        )
    except OSError as exc:
        return ExtractionResult(
            status=EntitlementStatus.ERROR,
            has_entitlements=False,
            entitlements_xml=None,
            error_message=str(exc),
            stderr=None,
        )

    stderr_text = _decode_bytes(completed.stderr)
    stdout_text = _decode_bytes(completed.stdout)
    raw_xml = stdout_text.strip() if stdout_text is not None else None

    if completed.returncode != 0:
        message = stderr_text or f"codesign exited with status {completed.returncode}"
        if _is_unsigned(stderr_text):
            return ExtractionResult(
                status=EntitlementStatus.UNSIGNED,
                has_entitlements=False,
                entitlements_xml=None,
                error_message=message,
                stderr=stderr_text,
            )
        return ExtractionResult(
            status=EntitlementStatus.ERROR,
            has_entitlements=False,
            entitlements_xml=raw_xml if _looks_like_plist(raw_xml) else None,
            error_message=message,
            stderr=stderr_text,
        )

    if raw_xml is None:
        return ExtractionResult(
            status=EntitlementStatus.NONE,
            has_entitlements=False,
            entitlements_xml=None,
            error_message=None,
            stderr=stderr_text,
        )

    if not _looks_like_plist(raw_xml):
        return ExtractionResult(
            status=EntitlementStatus.ERROR,
            has_entitlements=False,
            entitlements_xml=raw_xml,
            error_message="codesign returned non-plist entitlement output",
            stderr=stderr_text,
        )

    try:
        parsed = plistlib.loads(completed.stdout)
    except Exception as exc:
        return ExtractionResult(
            status=EntitlementStatus.ERROR,
            has_entitlements=False,
            entitlements_xml=raw_xml,
            error_message=f"failed to parse entitlement plist: {exc}",
            stderr=stderr_text,
        )

    has_entitlements = _plist_has_content(parsed)
    status = EntitlementStatus.EXTRACTED if has_entitlements else EntitlementStatus.NONE
    return ExtractionResult(
        status=status,
        has_entitlements=has_entitlements,
        entitlements_xml=raw_xml,
        error_message=None,
        stderr=stderr_text,
    )


def _decode_bytes(data: bytes | None) -> str | None:
    """Decode subprocess output safely."""

    if not data:
        return None
    return data.decode("utf-8", errors="replace").strip() or None


def _is_unsigned(stderr_text: str | None) -> bool:
    """Return ``True`` if stderr matches a known unsigned-file pattern."""

    if not stderr_text:
        return False
    lowered = stderr_text.lower()
    return any(marker in lowered for marker in _UNSIGNED_MARKERS)


def _looks_like_plist(raw_xml: str | None) -> bool:
    """Return ``True`` when output resembles an XML plist."""

    if raw_xml is None:
        return False
    return raw_xml.startswith("<?xml") or raw_xml.startswith("<plist")


def _plist_has_content(value: object) -> bool:
    """Return ``True`` if the parsed plist contains meaningful content."""

    if isinstance(value, dict):
        return bool(value)
    if isinstance(value, list):
        return bool(value)
    return value is not None
