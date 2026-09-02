import signal

import joblib
from models.ml_model_config import MODEL


def salva(sig, frm):
    joblib.dump(MODEL, "ids_model.pkl")
    print("[+] Modelo salvo")


signal.signal(signal.SIGUSR1, salva)
