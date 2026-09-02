"""
ML-based anomaly detection engine (Isolation Forest over per-packet feature
vectors).

Buffers the first `ML_BUFFER_SIZE` packet vectors to train the model, then
scores every subsequent packet and raises an alert when the anomaly score
exceeds `ML_THRESHOLD`.

Previously this module defined its own ad-hoc `alerta()` that duplicated
`logs.alert_logger.alerta()` (writing to a separate `ml_alerts.log` file via
plain `print()`/`open()`, no logging level). It now reuses the shared,
structured alert logger instead of maintaining a second implementation.
"""

import numpy as np
from features.packet_vectorizer import to_vector
from logs.alert_logger import alerta
from models.ml_model_config import BUFFER, MODEL, THRESH, TREINADO
from scapy.all import IP, sniff


def treina():
    global TREINADO
    if len(BUFFER) < 1000:
        return
    X = np.vstack(list(BUFFER))
    MODEL.fit(X)
    TREINADO = True
    print("[+] Modelo treinado com", len(BUFFER), "amostras")


def processa(p):
    if IP not in p:
        return
    v = to_vector(p)
    BUFFER.append(v)
    if not TREINADO:
        if len(BUFFER) % 1000 == 0:
            print("[+] Coletado", len(BUFFER))
        if len(BUFFER) == BUFFER.maxlen:
            treina()
        return
    score = MODEL.decision_function(v.reshape(1, -1))[0]
    if score > THRESH:
        alerta("Anomalia ML", p[IP].src, detalhe=f"score={score:.2f}")


def main():
    print("Capturando... (primeiros 10 000 pacotes = treino)")
    sniff(prn=processa, store=False, filter="ip")


if __name__ == "__main__":
    main()
