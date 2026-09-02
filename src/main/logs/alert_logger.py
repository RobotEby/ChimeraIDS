"""
Structured alerting: every alert is emitted to the console via Python's
standard `logging` module (leveled, timestamped, consistently formatted)
and appended as a line to a persistent alert log file.

Previously, two separate ad-hoc alert writers existed: this module (plain
`open("alerts.log", "a")`, no level, no console output) and a second,
near-duplicate implementation inside `rules/ml_detection_engine.py` (its own
`alerta()` writing to a different file, `ml_alerts.log`, with `print()`
instead of real logging). `ml_detection_engine.py` now uses this shared
alerta() instead of its own copy.

The file write intentionally stays a plain `open(path, "a")` call per alert
rather than a long-lived `logging.FileHandler`: this codebase's own test
suite exercises multiple independent working directories (via
`monkeypatch.chdir`) within a single process, and a handler opened once at
import time would keep writing to whatever path was current at that
moment, not the path relevant to each test. Resolving the path fresh on
every call keeps behavior correct under that usage pattern while still
being "structured" (leveled, ISO-ish timestamp, consistent fields).
"""

import logging
import time

from base import config

logger = logging.getLogger("chimera_ids")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))


def alerta(tipo, ip, detalhe=None):
    """
    Raise a security alert.

    `tipo` is the alert category (e.g. "DDoS", "PortScan", "SYN-Flood",
    "FlowAnomaly", "Anomalia ML"). `ip` is the source IP involved (or, for
    flow-level alerts, a short description of the flow). `detalhe` is an
    optional free-form extra field (e.g. an anomaly score).
    """
    msg = f"{tipo} ip={ip}"
    if detalhe is not None:
        msg += f" detalhe={detalhe}"

    logger.warning(msg)

    with open(config.RULE_ALERT_LOG_PATH, "a") as log:
        log.write(f"{time.time()} {msg}\n")
