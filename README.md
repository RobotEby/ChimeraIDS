# ChimeraIDS

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-Experimental-orange.svg)
![Tests](https://img.shields.io/badge/tests-35%20passing-brightgreen.svg)

An advanced, modular Intrusion Detection System (IDS) that monitors network traffic and detects anomalous behavior or patterns indicating potential attacks (e.g., DDoS, Port Scans, SYN Floods).

It performs packet capture and analysis using **Scapy** and supports a dual-engine detection approach:

1. **Rule-Based Detection:** Statistical baseline and deviation analysis.
2. **Machine Learning Anomaly Detection:** Behavioral learning using Isolation Forest.

---

## Table of Contents

- [ Project Overview](#-project-overview)
- [ Architecture](#️-architecture)
- [ Detection Approaches](#-detection-approaches)
- [1. Rule-Based IDS](#1️⃣-rule-based-ids)
- [2. Machine Learning IDS](#2️⃣-machine-learning-ids)
- [3. Temporal Flow Aggregation](#3️⃣-temporal-flow-aggregation-5s-windows)
- [Getting Started](#️-getting-started)
- [Testing Attacks](#-testing-attacks)
- [Model Persistence](#-model-persistence)
- [Future Improvements](#-future-improvements)
- [License](#-license)

---

## Project Overview

This system is built with a strong emphasis on modularity, scalability, and clean separation of responsibilities. Key capabilities include:

- **Live Traffic Capture:** Real-time packet interception.
- **Feature Extraction:** Translating raw packets into actionable numeric vectors.
- **Dynamic Baselines:** Learning standard network behavior on the fly.
- **Threat Detection:** Identifying DDoS, Port Scans, and SYN floods.
- **Flow Aggregation:** Grouping packets into 5-second windows to detect subtle, distributed attacks.
- **Persistent ML:** Logging alerts and saving ML models for continuous learning.

---

## Architecture

The codebase follows a strict `src/` layout, using absolute imports and separating data extraction from detection logic.

```text
ChimeraIDS/
├── src/
│ └── main/
│ ├── base/
│ │ ├── __init__.py
│ │ ├── baseline_dynamic_store.py
│ │ └── config.py
│ ├── data/
│ │ ├── __init__.py
│ │ └── packet_capture.py
│ ├── examples/
│ │ ├── __init__.py
│ │ └── mini_ids.py
│ ├── features/
│ │ ├── __init__.py
│ │ ├── packet_feature_extractor.py
│ │ └── packet_vectorizer.py
│ ├── logs/
│ │ ├── __init__.py
│ │ └── alert_logger.py
│ ├── models/
│ │ ├── __init__.py
│ │ ├── ml_model_config.py
│ │ └── ml_model_persistence.py
│ ├── rules/
│ │ ├── __init__.py
│ │ ├── rules_detection_engine.py
│ │ └── ml_detection_engine.py
│ ├── windows/
│ │ ├── __init__.py
│ │ └── traffic_window_aggregator.py
│ ├── __init__.py
│ └── requirements.txt
├── tests/
│ ├── conftest.py
│ ├── test_alert_logger.py
│ ├── test_baseline_dynamic_store.py
│ ├── test_config.py
│ ├── test_ml_model_config.py
│ ├── test_packet_vectorizer.py
│ ├── test_rules_detection_engine.py
│ └── test_window_aggregator.py
├── .github/
│ └── workflows/
│   └── ci.yml
├── .gitignore
├── pyproject.toml
├── LICENSE
└── README.md
```

## Detection Approaches

### 1. Rule-Based IDS

Builds a **dynamic baseline** during a warm-up period (a minimum number of
samples must be observed before any statistical check is trusted — see
"Fixes Applied During Audit" below) and flags anomalies based on deviation
from that baseline.

| Attack Type   | Detection Logic                                 | Base Metrics Monitored                           |
| ------------- | ------------------------------------------------ | ------------------------------------------------ |
| **DDoS**      | `PPS > μ + 3σ` (statistical)                     | Packets per second (PPS), Bytes per second (BPS) |
| **Port Scan** | `Unique ports (60s window) > fixed threshold`    | Unique destination ports per source IP           |
| **SYN Flood** | Excessive `SYN` without `ACK` (fixed threshold)  | TCP flag behavior                                |

Port scan detection uses a fixed threshold rather than a statistical
mean/stdev comparison — see "Fixes Applied During Audit" for why. All
thresholds are configurable via environment variables; see
`src/main/base/config.py`.

> 📍 _Implementation details found in:_ `main/rules/rules_detection_engine.py`

### 2. Machine Learning IDS

Instead of hardcoded thresholds, the ML engine uses an **Isolation Forest** model to learn "normal" traffic.

**Vectorization Process:** Each packet is transformed into a 12-dimensional numeric vector including: _Packet length, Protocol number, Source/Destination ports, TCP flags, Window size, TTL, Fragment ID, Payload length, Inter-arrival time, Payload entropy, and Same-source frequency._

> 📍 _Feature extraction:_ `main/features/packet_vectorizer.py` 📍 _Detection engine:_ `main/rules/ml_detection_engine.py`

### 3. Temporal Flow Aggregation (5s Windows)

Groups packets into 5-second flow windows based on `(proto, src_ip, dst_ip, dst_port)`. This is crucial for identifying:

- Slow scans

- Distributed UDP floods

- Low-rate intrusion attempts

> 📍 _Implementation details found in:_ `main/windows/traffic_window_aggregator.py`

---

## Getting Started

### Prerequisites

- Python 3.8+

- Linux environment recommended (root privileges required for raw packet capture).

### Installation

1.**Clone the repository and set up a virtual environment:**

```Bash
python -m venv .venv
```

2.**Activate the virtual environment:**

- **Windows:**

```Bash
.venv\Scripts\activate
```

- **Linux/macOS:**

```Bash
source .venv/bin/activate
```

3.**Install dependencies:**

```Bash
pip install -r src/main/requirements.txt
```

_Main packages: `scapy`, `numpy`, `pyod`, `scikit-learn`, `joblib`_

### Running the IDS

_Note: You may need to run these scripts with `sudo` or administrator privileges to allow network interface capture._

**Run Rule-Based Example:**

```Bash
sudo python src/main/examples/mini_ids.py
```

**Run ML-Based Detection:**

```Bash
sudo python src/main/rules/ml_detection_engine.py
```

_The system will automatically collect packets, train the model, begin detection, and write alerts to `alerts.log` / `ml_alerts.log` (via `main/logs/alert_logger.py`), as well as printing them to the console._

---

## Testing Attacks

You can verify the IDS functionality by simulating attacks using external tools like `hping3` and `nmap`.

**Simulate SYN Flood:**

```Bash
sudo hping3 -S -p 80 --flood <target-ip>
```

**Simulate UDP Flood:**

```Bash
sudo hping3 --udp --flood <target-ip>
```

**Simulate Port Scan:**

```Bash
nmap -sS <network-range>
```

---

## Configuration

All detection thresholds and window sizes live in `src/main/base/config.py`
and can be overridden with environment variables without editing source
code:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CHIMERA_DDOS_DESVIOS` | `3.0` | Standard deviations above the PPS baseline before a DDoS alert fires |
| `CHIMERA_SYN_FLOOD_LIMITE` | `100` | Consecutive SYNs (no ACK) from one IP before a SYN-flood alert fires |
| `CHIMERA_PORT_SCAN_LIMIAR` | `15` | Unique destination ports from one IP, within the baseline window, before a port-scan alert fires |
| `CHIMERA_MIN_AMOSTRAS_BASELINE` | `10` | Minimum samples required before the statistical DDoS check is trusted |
| `CHIMERA_JANELA_BASELINE_SEGUNDOS` | `60` | Sliding window size (seconds) for the rule-based baseline |
| `CHIMERA_JANELA_AGREGACAO_SEGUNDOS` | `5` | Window size (seconds) for temporal flow aggregation |
| `CHIMERA_HISTORICO_JANELAS` | `20` | How many past aggregation windows are kept per flow |
| `CHIMERA_MIN_JANELAS_PARA_ALERTA` | `5` | Minimum windows observed before flow-anomaly alerts are trusted |
| `CHIMERA_DESVIOS_PARA_ALERTA_FLUXO` | `3.0` | Standard deviations above a flow's own baseline before a flow-anomaly alert fires |
| `CHIMERA_ML_N_ESTIMATORS` | `200` | Isolation Forest tree count |
| `CHIMERA_ML_CONTAMINATION` | `0.02` | Isolation Forest expected outlier fraction |
| `CHIMERA_ML_BUFFER_SIZE` | `10000` | Packets buffered before the ML model trains |
| `CHIMERA_ML_THRESHOLD` | `0.7` | Anomaly score above which the ML engine alerts |
| `CHIMERA_RULE_ALERT_LOG` | `alerts.log` | Path for rule-engine and flow-aggregator alerts |
| `CHIMERA_ML_ALERT_LOG` | `ml_alerts.log` | Path for ML-engine alerts |
| `CHIMERA_LOG_LEVEL` | `INFO` | Console log level |

## Testing

```bash
pip install -e ".[dev]"
pytest
```

35 tests currently cover the shared baseline helpers, the rule-based engine
(DDoS, port scan, and SYN-flood detection, including the two regression
tests described below), the temporal flow aggregator, packet vectorization,
the ML model configuration, the structured alert logger, and the config
module's environment-variable overrides. All tests use synthetic, in-memory
packets built with Scapy — none depend on real captured or offensive
traffic, consistent with this project's defensive-only scope.

Lint: `ruff check .`

## Fixes Applied During Audit

An earlier audit pass found that **none of the three detection engines this
README describes could actually run**. Each failed with an `ImportError`
the moment it was imported, because each imported a key name from *itself*
rather than from where that name was actually supposed to come from:

- `models/ml_model_config.py` imported `IForest` from itself, instead of
  from `pyod.models.iforest`.
- `rules/rules_detection_engine.py` imported `pps`, `bps`, `uniq`,
  `syn_counter`, and the baseline mean/stdev variables from itself; none of
  those names were defined anywhere in the codebase. The real baseline
  logic only existed inside the standalone `examples/mini_ids.py` script
  and had never been ported into the "modular" engine.
- `windows/traffic_window_aggregator.py` imported `processa_vetor` from
  itself; that function was never defined anywhere. This module (plus a
  byte-for-byte duplicate file, `traffic-window-aggregator.py`, whose name
  wasn't even a valid Python module name) was completely dead, orphaned
  code — nothing else in the codebase called it.

Once these were fixed and the engines could actually run for the first
time, two further bugs surfaced immediately under test:

1. The DDoS check false-positived on literally the first packet from any
   source IP (an empty/1-sample baseline has mean=0, stdev=0, so
   `1 > 0 + 3*0` is trivially true). Fixed with a minimum-sample warm-up
   gate before the statistical check is trusted.
2. The inherited port-scan formula (`mu = len(uniq) - 1`, fixed
   `sigma = 2`) reduced to `len(uniq) > len(uniq) + 5`, which is false for
   every possible value — this check could never fire, for any input, ever.
   It also compared against an unbounded, never-time-trimmed set of
   lifetime ports rather than recent behavior. Replaced with a fixed,
   configurable threshold on unique ports within the trailing baseline
   window (the same kind of approach already used for SYN-flood detection).

`src/main/base/__init__.py` was also misnamed `_init_.py` (single
underscores), which meant it wasn't recognized as a Python package
initializer at all.

All three engines, the temporal flow aggregator, and these two additional
logic bugs now have regression tests (see "Testing" above) so they cannot
silently regress.

## Model Persistence

The ML architecture supports continuous learning. Models can be saved and reloaded via `main/models/ml_model_persistence.py`. This ensures:

- Model reuse after system restarts.

- Long-term anomaly memory.

- Reduced training overhead on subsequent runs.

---

## Design Principles

- **Clear Separation:** Modular detection engines independent of capture and configuration logic.

- **Extensible Architecture:** Designed to easily plug in advanced neural networks (LSTM, Seq2Seq, etc.).

## Future Improvements

- \[ \] LSTM Autoencoder implementation

- \[ \] Seq2Seq + Attention mechanisms

- \[ \] Real-time visualization dashboard

- \[ \] Automatic firewall blocking integration

- \[ \] Flow export to Elastic/Prometheus

- \[ \] GPU-accelerated ML

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Authors <a name = "authors"></a>

- [@Kerlon Amaral](https://github.com/RobotEby) - Idea & Initial work