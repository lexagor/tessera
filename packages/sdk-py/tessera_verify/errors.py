"""Typed SDK errors."""

from __future__ import annotations

from typing import Any


class TesseraError(Exception):
    """Base class for Tessera SDK failures."""


class TesseraTransportError(TesseraError):
    """The broker could not be reached or the connection failed."""


class TesseraHTTPError(TesseraError):
    """The broker returned a non-success HTTP response."""

    def __init__(self, message: str, status_code: int, body: Any) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body
