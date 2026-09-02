"""
Centralized configuration for ChimeraIDS.

Every detection threshold and window size that was previously a bare
constant scattered across `rules_detection_engine.py`,
`traffic_window_aggregator.py`, and `ml_model_config.py` lives here instead,
with environment-variable overrides so a deployment can tune sensitivity
without editing source code.

All values have the same defaults as the original hardcoded constants, so
behavior is unchanged unless a CHIMERA_* environment variable is set.
"""

import os


def _float_env(name, default):
    value = os.environ.get(name)
    return float(value) if value is not None else default


def _int_env(name, default):
    value = os.environ.get(name)
    return int(value) if value is not None else default


# --- Rule-based engine (rules/rules_detection_engine.py) -------------------

JANELA_BASELINE_SEGUNDOS = _float_env("CHIMERA_JANELA_BASELINE_SEGUNDOS", 60.0)
DDOS_DESVIOS = _float_env("CHIMERA_DDOS_DESVIOS", 3.0)
SYN_FLOOD_LIMITE = _int_env("CHIMERA_SYN_FLOOD_LIMITE", 100)
PORT_SCAN_LIMIAR = _int_env("CHIMERA_PORT_SCAN_LIMIAR", 15)
MIN_AMOSTRAS_BASELINE = _int_env("CHIMERA_MIN_AMOSTRAS_BASELINE", 10)

# --- Temporal flow aggregation (windows/traffic_window_aggregator.py) ------

JANELA_AGREGACAO_SEGUNDOS = _float_env("CHIMERA_JANELA_AGREGACAO_SEGUNDOS", 5.0)
HISTORICO_JANELAS = _int_env("CHIMERA_HISTORICO_JANELAS", 20)
MIN_JANELAS_PARA_ALERTA = _int_env("CHIMERA_MIN_JANELAS_PARA_ALERTA", 5)
DESVIOS_PARA_ALERTA_FLUXO = _float_env("CHIMERA_DESVIOS_PARA_ALERTA_FLUXO", 3.0)

# --- ML engine (models/ml_model_config.py) ----------------------------------

ML_N_ESTIMATORS = _int_env("CHIMERA_ML_N_ESTIMATORS", 200)
ML_CONTAMINATION = _float_env("CHIMERA_ML_CONTAMINATION", 0.02)
ML_BUFFER_SIZE = _int_env("CHIMERA_ML_BUFFER_SIZE", 10000)
ML_THRESHOLD = _float_env("CHIMERA_ML_THRESHOLD", 0.7)

# --- Logging -----------------------------------------------------------------

RULE_ALERT_LOG_PATH = os.environ.get("CHIMERA_RULE_ALERT_LOG", "alerts.log")
ML_ALERT_LOG_PATH = os.environ.get("CHIMERA_ML_ALERT_LOG", "ml_alerts.log")
LOG_LEVEL = os.environ.get("CHIMERA_LOG_LEVEL", "INFO")
