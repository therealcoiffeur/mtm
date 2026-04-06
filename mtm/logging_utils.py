"""Logging helpers."""

from __future__ import annotations

import logging


def configure_logging(verbose: bool) -> None:
    """Configure process-wide logging."""

    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(level)
    root_logger.addHandler(handler)
