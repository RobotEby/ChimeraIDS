"""Saving the Isolation Forest to disk.

Earlier this module registered a `SIGUSR1` handler as an import side effect and
nothing imported it, so the documented "send SIGUSR1 to save the model" never
worked; it would also have crashed on Windows, which has no `SIGUSR1`.
Registration is now explicit (`instala_handler_de_salvamento`, called from the
ML engine's `main()`) and skipped on platforms without the signal.
"""

import signal

import joblib

from chimera_ids.models.ml_model_config import MODEL

CAMINHO_PADRAO = "ids_model.pkl"


def salva(sig=None, frm=None, caminho=CAMINHO_PADRAO):
    """Persist the current model. Signature matches a `signal` handler."""
    joblib.dump(MODEL, caminho)
    print("[+] Modelo salvo")
    return caminho


def carrega(caminho=CAMINHO_PADRAO):
    """Load a model previously written by `salva`."""
    return joblib.load(caminho)


def instala_handler_de_salvamento():
    """Save the model when the process receives SIGUSR1. Returns True if installed."""
    if not hasattr(signal, "SIGUSR1"):
        return False
    signal.signal(signal.SIGUSR1, salva)
    return True
