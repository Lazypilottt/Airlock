"""Lazy ONNX Runtime adapter for Llama Prompt Guard 2."""

from __future__ import annotations

import hashlib
import importlib
import logging
import math
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from airlock.config import ClassifierConfig
from airlock.detect.normalize import normalize

LOGGER = logging.getLogger(__name__)


class ModelUnavailable(RuntimeError):
    """Raised when the configured classifier cannot be loaded."""


class Scorer(Protocol):
    """Small protocol used by tests and the lazy runtime scorer."""

    def score(self, text: str) -> tuple[float, tuple[int, int] | None]: ...


@dataclass(frozen=True)
class Window:
    """A token window and its character span."""

    text: str
    start: int
    end: int


class PromptGuardClassifier:
    """Lazy, cached Prompt Guard 2 classifier."""

    def __init__(
        self,
        data_dir: Path,
        config: ClassifierConfig | None = None,
        runtime_scorer: Scorer | None = None,
    ) -> None:
        self.data_dir = data_dir
        self.config = config or ClassifierConfig()
        self._runtime_scorer = runtime_scorer
        self._session: Any | None = None
        self._tokenizer: Any | None = None
        self._cache: OrderedDict[str, tuple[float, tuple[int, int] | None]] = OrderedDict()
        self._unavailable_logged = False

    @property
    def model_dir(self) -> Path:
        return self.data_dir / "models" / f"promptguard-{self.config.model_name.lower()}"

    def _log_unavailable(self, reason: str) -> None:
        if not self._unavailable_logged:
            LOGGER.warning("classifier unavailable: %s", reason)
            self._unavailable_logged = True

    def _load(self) -> None:
        if self._runtime_scorer is not None or self._session is not None:
            return
        if not self.model_dir.is_dir() or not (self.model_dir / "model.int8.onnx").is_file():
            reason = f"model not found at {self.model_dir}"
            self._log_unavailable(reason)
            raise ModelUnavailable(reason)
        try:
            ort = importlib.import_module("onnxruntime")
            transformers = importlib.import_module("transformers")
        except ImportError as exc:
            reason = f"optional ONNX dependencies are unavailable: {exc}"
            self._log_unavailable(reason)
            raise ModelUnavailable(reason) from exc
        try:
            self._tokenizer = transformers.AutoTokenizer.from_pretrained(self.model_dir)
            self._session = ort.InferenceSession(
                str(self.model_dir / "model.int8.onnx"),
                providers=["CPUExecutionProvider"],
            )
        except Exception as exc:
            reason = f"model load failed: {exc}"
            self._log_unavailable(reason)
            raise ModelUnavailable(reason) from exc

    def _windows(self, text: str) -> list[Window]:
        self._load()
        if self._runtime_scorer is not None:
            return [Window(text, 0, len(text))]
        assert self._tokenizer is not None
        encoded = self._tokenizer(
            text,
            add_special_tokens=True,
            return_offsets_mapping=True,
            truncation=False,
        )
        offsets = encoded["offset_mapping"]
        input_ids = encoded["input_ids"]
        content_limit = 512
        step = content_limit - 64
        windows: list[Window] = []
        for start in range(0, len(input_ids), step):
            end = min(start + content_limit, len(input_ids))
            char_start = offsets[start][0]
            char_end = offsets[end - 1][1]
            windows.append(Window(text[char_start:char_end], char_start, char_end))
            if end == len(input_ids):
                break
        return windows or [Window("", 0, 0)]

    def _score_batch(self, windows: list[Window]) -> list[float]:
        if self._runtime_scorer is not None:
            return [self._runtime_scorer.score(window.text)[0] for window in windows]
        assert self._tokenizer is not None
        assert self._session is not None
        batch = self._tokenizer(
            [window.text for window in windows],
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="np",
        )
        inputs = {
            item.name: batch[item.name] for item in self._session.get_inputs() if item.name in batch
        }
        outputs = self._session.run(None, inputs)
        logits = outputs[0]
        probabilities: list[float] = []
        for row in logits:
            maximum = max(float(value) for value in row)
            exponents = [math.exp(float(value) - maximum) for value in row]
            total = sum(exponents)
            probabilities.append(exponents[1] / total)
        return probabilities

    def score(self, text: str) -> tuple[float, tuple[int, int] | None]:
        """Return malicious probability and the original character span."""
        normalized = normalize(text).text
        key = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        cached = self._cache.get(key)
        if cached is not None:
            self._cache.move_to_end(key)
            return cached
        windows = self._windows(normalized)
        probabilities = self._score_batch(windows)
        index = max(range(len(probabilities)), key=probabilities.__getitem__)
        result = (probabilities[index], (windows[index].start, windows[index].end))
        if self.config.cache_size:
            self._cache[key] = result
            self._cache.move_to_end(key)
            while len(self._cache) > self.config.cache_size:
                self._cache.popitem(last=False)
        return result


__all__ = ["ModelUnavailable", "PromptGuardClassifier", "Scorer"]
