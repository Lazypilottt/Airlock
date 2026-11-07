#!/usr/bin/env python3
"""Export and quantize Meta Llama Prompt Guard 2.

Before running this script, accept Meta's Llama license on Hugging Face and
export HF_TOKEN in the environment. The gated model files cannot be downloaded
without both steps.
"""

from __future__ import annotations

import argparse
import importlib
import os
from pathlib import Path

MODEL_IDS = {
    "22M": "meta-llama/Llama-Prompt-Guard-2-22M",
    "86M": "meta-llama/Llama-Prompt-Guard-2-86M",
}


def export_model(variant: str, data_dir: Path) -> Path:
    """Download, export to ONNX, and dynamically quantize one model."""
    token = os.environ.get("HF_TOKEN")
    if not token:
        raise SystemExit(
            "Set HF_TOKEN after accepting Meta's Llama license on Hugging Face "
            "(https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M)."
        )
    try:
        optimum = importlib.import_module("optimum.onnxruntime")
        quantization = importlib.import_module("onnxruntime.quantization")
        transformers = importlib.import_module("transformers")
    except ImportError as exc:
        raise SystemExit(
            "Install the export extra first, in its own environment: "
            "pip install 'airlock-mcp[classifier-export]'"
        ) from exc

    model_id = MODEL_IDS[variant]
    output = data_dir / "models" / f"promptguard-{variant.lower()}"
    output.mkdir(parents=True, exist_ok=True)
    model = optimum.ORTModelForSequenceClassification.from_pretrained(
        model_id, export=True, token=token
    )
    tokenizer = transformers.AutoTokenizer.from_pretrained(model_id, token=token)
    temporary = output / "model.onnx"
    model.save_pretrained(output)
    tokenizer.save_pretrained(output)
    exported = output / "model.onnx"
    if exported.exists():
        temporary = exported
    quantization.quantize_dynamic(
        str(temporary), str(output / "model.int8.onnx"), weight_type=quantization.QuantType.QInt8
    )
    if temporary.name != "model.int8.onnx" and temporary.exists():
        temporary.unlink()
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=sorted(MODEL_IDS), default="22M")
    parser.add_argument("--data-dir", type=Path, default=Path.home() / ".config" / "airlock")
    args = parser.parse_args()
    print(export_model(args.variant, args.data_dir))


if __name__ == "__main__":
    main()
