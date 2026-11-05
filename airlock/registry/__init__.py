"""Tool registry, integrity pinning, and description checking for Airlock."""

from __future__ import annotations

from airlock.registry.checks import DescriptionCheck, L1DescriptionCheck, StubDescriptionCheck
from airlock.registry.labels import (
    ArgRole,
    Label,
    LabelOrigin,
    LabelPack,
    LabelResolver,
    ToolLabels,
    infer_labels,
    load_label_packs,
)
from airlock.registry.store import (
    ToolRegistry,
    compute_tool_hash,
    generate_unified_diff,
    labels_from_row,
)

__all__ = [
    "ArgRole",
    "DescriptionCheck",
    "L1DescriptionCheck",
    "Label",
    "LabelOrigin",
    "LabelPack",
    "LabelResolver",
    "StubDescriptionCheck",
    "ToolLabels",
    "ToolRegistry",
    "compute_tool_hash",
    "generate_unified_diff",
    "infer_labels",
    "labels_from_row",
    "load_label_packs",
]
