"""Package for parsing RFC 6266 Content-Disposition headers."""

from __future__ import annotations

from ._main import (
    ContentDisposition,
    parse,
    parse_filename,
    requests_response_to_filename,
    secure_filename,
)

__version__ = "1000.0.2"

__all__ = (
    "ContentDisposition",
    "parse",
    "parse_filename",
    "requests_response_to_filename",
    "secure_filename",
)
