# Training airlock-v1

Airlock's own classifier is trained on a GPU runtime (a free Colab or Kaggle
notebook). Nothing here needs to run on your machine; at the end you copy
one folder (about 150 MB for a base-size model) into Airlock's data directory.

## 1. Notebook setup

Colab: *Runtime → Change runtime type → T4 GPU*. Kaggle: *Accelerator → GPU T4*.

```bash
!git clone https://github.com/Lazypilottt/Airlock.git && cd Airlock
%cd Airlock
!pip install -q "transformers>=4.48" "optimum[onnxruntime]" datasets accelerate
```

The repository is private: in Colab, use a fine-grained GitHub token with read
access (`https://<token>@github.com/Lazypilottt/Airlock.git`), or upload a zip.

For the Prompt Guard comparison, accept Meta's licence on
<https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M> and add your
token as a notebook secret named `HF_TOKEN`:

```python
import os
from google.colab import userdata  # Kaggle: from kaggle_secrets import UserSecretsClient

os.environ["HF_TOKEN"] = userdata.get("HF_TOKEN")
```

## 2. Build the dataset

```bash
!python -m scripts.build_dataset --out data/classifier
!cat data/classifier/DATASHEET.md
```

Sources and licences are listed in the datasheet. AgentDojo's attack strings
are removed from every split.

## 3. Train, export, compare

```bash
!python -m scripts.train_classifier --data data/classifier --out runs \
    --base-model microsoft/deberta-v3-small --compare-promptguard
!python -m scripts.train_classifier --data data/classifier --out runs \
    --base-model answerdotai/ModernBERT-base --compare-promptguard
```

Each run writes `runs/<model>/report.md` (precision, recall, F1, false-positive
rate at the threshold chosen on validation, CPU latency of the int8 model,
Prompt Guard 2 on the same test set) and `runs/<model>/airlock-v1/`. A T4
needs roughly 20 to 60 minutes per model for the default dataset size.

## 4. Bring the model home

Download `runs/<best model>/airlock-v1/` (zip it in the notebook) and unpack
it to `~/.config/airlock/models/airlock-v1/`, so that
`~/.config/airlock/models/airlock-v1/model.int8.onnx` exists. Install the
runtime classifier extra locally (`uv sync --extra classifier`; the notebook's
`optimum` toolchain is only needed for export) and select it:

```yaml
# ~/.config/airlock/airlock.yaml
classifier: airlock-v1
```

`report.md` also gives the threshold chosen on validation (stored in
`airlock-model.json`); use it to tune `redact_above` / `block_above`.
