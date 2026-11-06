#!/usr/bin/env python3
"""Build the training data for Airlock's own injection classifier.

Writes ``data/classifier/{train,validation,test}.jsonl`` and ``DATASHEET.md``.

    python -m scripts.build_dataset                     # public datasets + synthetic
    python -m scripts.build_dataset --synthetic-only    # no downloads

The public datasets are fetched with the `datasets` package (installed on the
Colab/Kaggle runtime that trains the model; see docs/training.md). Licences
are recorded in `scripts/classifier_data.py` and in the datasheet.
"""

from __future__ import annotations

import argparse
import importlib
import random
from pathlib import Path

from scripts.classifier_data import (
    HF_SOURCES,
    HFSource,
    Sample,
    build_synthetic,
    finalise,
    insert_at_random,
    write_dataset,
)


def load_hf_source(source: HFSource, max_rows: int, seed: int) -> list[Sample]:
    """Rows of one public dataset as samples (one group per row)."""
    try:
        datasets = importlib.import_module("datasets")
    except ImportError as exc:
        raise SystemExit(
            "Install `datasets` (pip install datasets) or pass --synthetic-only"
        ) from exc
    samples: list[Sample] = []
    for split in source.splits:
        rows = datasets.load_dataset(source.repo, split=split)
        for index, row in enumerate(rows):
            text = "\n".join(
                str(row[column]) for column in source.text_columns if row.get(column)
            ).strip()
            if not text:
                continue
            label = int(row[source.label_column]) if source.label_column else 1
            group = f"{source.repo}:{split}:{index}"
            samples.append(Sample(text, label, source.repo, group, f"public:{split}"))
    rng = random.Random(seed)
    rng.shuffle(samples)
    return samples[:max_rows]


def embed_public_injections(samples: list[Sample], seed: int) -> list[Sample]:
    """Also hide half of the public injections inside synthetic tool outputs (same group)."""
    from scripts.classifier_data import CARRIERS

    rng = random.Random(seed)
    kinds = sorted(CARRIERS)
    embedded: list[Sample] = []
    for sample in samples:
        if sample.label == 1 and rng.random() < 0.5:
            carrier = CARRIERS[rng.choice(kinds)](rng)
            embedded.append(
                Sample(
                    insert_at_random(carrier, sample.text, rng),
                    1,
                    sample.source,
                    sample.group,
                    f"{sample.kind}:embedded",
                )
            )
    return embedded


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("data/classifier"))
    parser.add_argument("--synthetic-documents", type=int, default=6000)
    parser.add_argument("--max-per-source", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--synthetic-only", action="store_true", help="Skip the public datasets.")
    args = parser.parse_args()

    samples = build_synthetic(args.synthetic_documents, seed=args.seed)
    sources = [] if args.synthetic_only else list(HF_SOURCES)
    for source in sources:
        public = load_hf_source(source, args.max_per_source, args.seed)
        samples += public + embed_public_injections(public, args.seed)
        print(f"{source.repo}: {len(public)} rows ({source.licence})")
    splits, removed = finalise(samples, seed=args.seed)
    sheet = write_dataset(args.out, splits, removed, sources, args.seed)
    for name, rows in splits.items():
        print(f"{name}: {len(rows)} samples, {sum(s.label for s in rows)} injections")
    print(f"Removed: {removed}")
    print(sheet)


if __name__ == "__main__":
    main()
