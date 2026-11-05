"""Taint tracking: values from untrusted or secret tool results must not reach sinks."""

from __future__ import annotations

from airlock.taint.extract import ExtractedValue, extract_values
from airlock.taint.table import TaintEntry, TaintMatch, TaintTable
from airlock.taint.tracker import (
    TaintCheck,
    TaintHit,
    TaintRecordCheck,
    TrustedValues,
    walk_arguments,
)

__all__ = [
    "ExtractedValue",
    "TaintCheck",
    "TaintEntry",
    "TaintHit",
    "TaintMatch",
    "TaintRecordCheck",
    "TaintTable",
    "TrustedValues",
    "extract_values",
    "walk_arguments",
]
