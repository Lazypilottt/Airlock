#!/usr/bin/env python3
"""Fine-tune Airlock's injection classifier, export it to ONNX int8 and report.

Meant for a GPU runtime (free Colab or Kaggle); see docs/training.md.

    python -m scripts.train_classifier --data data/classifier --out runs \\
        --base-model answerdotai/ModernBERT-base --compare-promptguard

Outputs ``<out>/<run>/airlock-v1/`` (``model.int8.onnx`` and tokenizer files,
the layout Airlock loads from ``data_dir/models/airlock-v1``) and
``<out>/<run>/report.md`` / ``report.json`` with precision, recall, F1 and
false-positive rate at the chosen threshold, CPU latency of the int8 model,
and the same numbers for Prompt Guard 2 on the same test set.

The helpers at the top have no ML dependencies so they can be unit-tested.
"""

from __future__ import annotations

import argparse
import importlib
import json
import statistics
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

BASE_MODELS = ("answerdotai/ModernBERT-base", "microsoft/deberta-v3-small")
PROMPTGUARD_22M = "meta-llama/Llama-Prompt-Guard-2-22M"
MAX_LENGTH = 512


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def class_weights(labels: Sequence[int]) -> list[float]:
    """Inverse-frequency weights for labels 0 and 1, normalised to average 1."""
    counts = [sum(1 for label in labels if label == value) for value in (0, 1)]
    total = sum(counts)
    if not total or not all(counts):
        return [1.0, 1.0]
    return [total / (2 * count) for count in counts]


@dataclass(frozen=True)
class Metrics:
    threshold: float
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    support: int


def metrics_at(labels: Sequence[int], scores: Sequence[float], threshold: float) -> Metrics:
    tp = fp = tn = fn = 0
    for label, score in zip(labels, scores, strict=True):
        predicted = score >= threshold
        if predicted and label:
            tp += 1
        elif predicted:
            fp += 1
        elif label:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return Metrics(threshold, precision, recall, f1, fpr, len(labels))


def choose_threshold(
    labels: Sequence[int], scores: Sequence[float], max_fpr: float = 0.01
) -> Metrics:
    """Best-F1 threshold among those with a false-positive rate of at most ``max_fpr``.

    Falls back to the best-F1 threshold overall if none meets the limit.
    Chosen on validation data, then applied unchanged to the test set.
    """
    candidates = sorted({round(score, 4) for score in scores} | {0.5})
    evaluated = [metrics_at(labels, scores, threshold) for threshold in candidates]
    within = [m for m in evaluated if m.false_positive_rate <= max_fpr]
    pool = within or evaluated
    return max(pool, key=lambda m: (m.f1, m.threshold))


def latency_summary(samples_ms: Sequence[float]) -> dict[str, float]:
    ordered = sorted(samples_ms)
    if not ordered:
        return {"p50_ms": 0.0, "p95_ms": 0.0}
    return {
        "p50_ms": statistics.median(ordered),
        "p95_ms": ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))],
    }


def read_jsonl(path: Path) -> tuple[list[str], list[int]]:
    texts: list[str] = []
    labels: list[int] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            texts.append(row["text"])
            labels.append(int(row["label"]))
    return texts, labels


def render_report(report: dict[str, Any]) -> str:
    lines = [
        f"# Classifier report: {report['run']}",
        "",
        f"Base model: `{report['base_model']}`. Threshold chosen on validation "
        f"(best F1 with FPR <= {report['max_fpr']:.0%}): {report['threshold']:.4f}.",
        "",
        "| Model (test set) | Threshold | Precision | Recall | F1 | FPR | CPU p50/p95 ms |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in report["rows"]:
        m = row["metrics"]
        latency = row.get("latency")
        latency_text = f"{latency['p50_ms']:.1f} / {latency['p95_ms']:.1f}" if latency else "n/a"
        lines.append(
            f"| {row['name']} | {m['threshold']:.3f} | {m['precision']:.3f} | {m['recall']:.3f} "
            f"| {m['f1']:.3f} | {m['false_positive_rate']:.3f} | {latency_text} |"
        )
    lines += ["", f"Test samples: {report['test_size']}."]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Training (needs torch, transformers, optimum[onnxruntime])
# ---------------------------------------------------------------------------


def _require(name: str) -> Any:
    try:
        return importlib.import_module(name)
    except ImportError as exc:
        raise SystemExit(
            f"{name} is missing. On Colab: pip install 'transformers>=4.48' "
            "'optimum[onnxruntime]' datasets accelerate"
        ) from exc


def _probabilities(logits: Any) -> list[float]:
    np = _require("numpy")
    values = np.asarray(logits, dtype="float64")
    values = values - values.max(axis=1, keepdims=True)
    exp = np.exp(values)
    return [float(p) for p in (exp[:, 1] / exp.sum(axis=1))]


def train(args: argparse.Namespace) -> Path:
    torch = _require("torch")
    transformers = _require("transformers")
    datasets = _require("datasets")

    run = args.run or args.base_model.split("/")[-1].lower()
    run_dir = args.out / run
    run_dir.mkdir(parents=True, exist_ok=True)
    train_texts, train_labels = read_jsonl(args.data / "train.jsonl")
    val_texts, val_labels = read_jsonl(args.data / "validation.jsonl")
    test_texts, test_labels = read_jsonl(args.data / "test.jsonl")

    tokenizer = transformers.AutoTokenizer.from_pretrained(args.base_model)
    model = transformers.AutoModelForSequenceClassification.from_pretrained(
        args.base_model,
        num_labels=2,
        id2label={0: "BENIGN", 1: "INJECTION"},
        label2id={"BENIGN": 0, "INJECTION": 1},
    )

    def encode(texts: list[str], labels: list[int]) -> Any:
        data = datasets.Dataset.from_dict({"text": texts, "label": labels})
        return data.map(
            lambda batch: tokenizer(batch["text"], truncation=True, max_length=MAX_LENGTH),
            batched=True,
            remove_columns=["text"],
        )

    train_set, val_set = encode(train_texts, train_labels), encode(val_texts, val_labels)
    weights = torch.tensor(class_weights(train_labels), dtype=torch.float)

    class WeightedTrainer(transformers.Trainer):  # type: ignore[misc]
        def compute_loss(  # type: ignore[no-untyped-def]
            self, model, inputs, return_outputs=False, num_items_in_batch=None
        ):
            labels = inputs.pop("labels")
            outputs = model(**inputs)
            loss_fn = torch.nn.CrossEntropyLoss(weight=weights.to(outputs.logits.device))
            loss = loss_fn(outputs.logits, labels)
            return (loss, outputs) if return_outputs else loss

    def compute_metrics(prediction: Any) -> dict[str, float]:
        scores = _probabilities(prediction.predictions)
        m = metrics_at(list(prediction.label_ids), scores, 0.5)
        return {
            "f1": m.f1,
            "precision": m.precision,
            "recall": m.recall,
            "fpr": m.false_positive_rate,
        }

    training_args = transformers.TrainingArguments(
        output_dir=str(run_dir / "checkpoints"),
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=1,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        num_train_epochs=args.epochs,
        learning_rate=args.learning_rate,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        warmup_ratio=0.06,
        weight_decay=0.01,
        fp16=bool(torch.cuda.is_available()),
        report_to=[],
        seed=args.seed,
    )
    trainer = WeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=train_set,
        eval_dataset=val_set,
        processing_class=tokenizer,
        data_collator=transformers.DataCollatorWithPadding(tokenizer),
        compute_metrics=compute_metrics,
        callbacks=[transformers.EarlyStoppingCallback(early_stopping_patience=2)],
    )
    trainer.train()
    best = run_dir / "best"
    trainer.save_model(str(best))
    tokenizer.save_pretrained(str(best))

    val_scores = _probabilities(trainer.predict(val_set).predictions)
    chosen = choose_threshold(val_labels, val_scores, args.max_fpr)

    exported = export_int8(best, run_dir / "airlock-v1")
    test_scores, latency = score_onnx(exported, test_texts)
    rows: list[dict[str, Any]] = [
        {
            "name": "airlock-v1 (int8 ONNX)",
            "metrics": asdict(metrics_at(test_labels, test_scores, chosen.threshold)),
            "latency": latency,
        }
    ]
    if args.compare_promptguard:
        pg_scores, pg_latency = score_promptguard(test_texts)
        for threshold in (0.5, 0.85):
            rows.append(
                {
                    "name": f"Prompt Guard 2 22M (at {threshold})",
                    "metrics": asdict(metrics_at(test_labels, pg_scores, threshold)),
                    "latency": pg_latency,
                }
            )
    report = {
        "run": run,
        "base_model": args.base_model,
        "max_fpr": args.max_fpr,
        "threshold": chosen.threshold,
        "validation": asdict(chosen),
        "test_size": len(test_texts),
        "rows": rows,
    }
    (exported / "airlock-model.json").write_text(
        json.dumps({"base_model": args.base_model, "threshold": chosen.threshold}, indent=2),
        encoding="utf-8",
    )
    (run_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (run_dir / "report.md").write_text(render_report(report), encoding="utf-8")
    print(render_report(report))
    return run_dir


def export_int8(model_dir: Path, out_dir: Path) -> Path:
    """The Task 7 pipeline: optimum ONNX export, then dynamic int8 quantisation."""
    optimum = _require("optimum.onnxruntime")
    quantization = _require("onnxruntime.quantization")
    transformers = _require("transformers")
    out_dir.mkdir(parents=True, exist_ok=True)
    model = optimum.ORTModelForSequenceClassification.from_pretrained(model_dir, export=True)
    model.save_pretrained(out_dir)
    transformers.AutoTokenizer.from_pretrained(model_dir).save_pretrained(out_dir)
    quantization.quantize_dynamic(
        str(out_dir / "model.onnx"),
        str(out_dir / "model.int8.onnx"),
        weight_type=quantization.QuantType.QInt8,
    )
    (out_dir / "model.onnx").unlink(missing_ok=True)
    return out_dir


def score_onnx(model_dir: Path, texts: list[str]) -> tuple[list[float], dict[str, float]]:
    """Score texts one at a time on CPU with the int8 model (latency per text)."""
    ort = _require("onnxruntime")
    transformers = _require("transformers")
    tokenizer = transformers.AutoTokenizer.from_pretrained(model_dir)
    session = ort.InferenceSession(
        str(model_dir / "model.int8.onnx"), providers=["CPUExecutionProvider"]
    )
    names = {item.name for item in session.get_inputs()}
    scores: list[float] = []
    timings: list[float] = []
    for text in texts:
        started = time.perf_counter()
        batch = tokenizer(text, truncation=True, max_length=MAX_LENGTH, return_tensors="np")
        logits = session.run(None, {k: v for k, v in batch.items() if k in names})[0]
        timings.append((time.perf_counter() - started) * 1000)
        scores.extend(_probabilities(logits))
    return scores, latency_summary(timings)


def score_promptguard(texts: list[str]) -> tuple[list[float], dict[str, float]]:
    """Prompt Guard 2 22M (gated: accept Meta's licence and set HF_TOKEN)."""
    torch = _require("torch")
    transformers = _require("transformers")
    tokenizer = transformers.AutoTokenizer.from_pretrained(PROMPTGUARD_22M)
    model = transformers.AutoModelForSequenceClassification.from_pretrained(PROMPTGUARD_22M)
    model.eval()
    scores: list[float] = []
    timings: list[float] = []
    with torch.no_grad():
        for text in texts:
            started = time.perf_counter()
            batch = tokenizer(text, truncation=True, max_length=MAX_LENGTH, return_tensors="pt")
            logits = model(**batch).logits
            timings.append((time.perf_counter() - started) * 1000)
            scores.extend(_probabilities(logits.numpy()))
    return scores, latency_summary(timings)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data/classifier"))
    parser.add_argument("--out", type=Path, default=Path("runs"))
    parser.add_argument("--base-model", default=BASE_MODELS[0])
    parser.add_argument("--run", default=None, help="Run name (default: base model name).")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--learning-rate", type=float, default=3e-5)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument(
        "--compare-promptguard",
        action="store_true",
        help="Also score the test set with Prompt Guard 2 22M (needs HF_TOKEN).",
    )
    train(parser.parse_args())


if __name__ == "__main__":
    main()
