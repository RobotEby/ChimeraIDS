import importlib
import sys
from collections import deque

import numpy as np
import pytest
from scapy.all import IP, TCP, Ether, Raw

import chimera_ids.features.packet_vectorizer as vectorizer
import chimera_ids.rules.ml_detection_engine as engine


class FakeModel:
    """Stands in for the Isolation Forest so the engine logic can be tested alone."""

    def __init__(self, score=0.0):
        self.score = score
        self.fit_calls = []

    def fit(self, X):
        self.fit_calls.append(X.shape)

    def decision_function(self, X):
        assert X.shape == (1, 12), "scoring must receive a single (1, 12) row"
        return np.array([self.score])


@pytest.fixture(autouse=True)
def isolated_engine(monkeypatch):
    """Fresh buffer, untrained state and a recording alert sink for every test."""
    alerts = []
    monkeypatch.setattr(engine, "BUFFER", deque(maxlen=5))
    monkeypatch.setattr(engine, "MIN_AMOSTRAS_TREINO", 5)
    monkeypatch.setattr(engine, "TREINADO", False)
    monkeypatch.setattr(engine, "MODEL", FakeModel())
    monkeypatch.setattr(
        engine, "alerta", lambda tipo, ip, **kw: alerts.append((tipo, ip, kw.get("detalhe")))
    )
    vectorizer.last_seen.clear()
    return alerts


def packet(src="10.0.0.1", sport=1234, ttl=64):
    return IP(src=src, dst="10.0.0.2", ttl=ttl) / TCP(sport=sport, dport=80, flags="S")


def feed(n, **kw):
    for i in range(n):
        engine.processa(packet(sport=1000 + i, **kw))


def test_processa_ignores_packets_without_an_ip_layer(isolated_engine):
    engine.processa(Ether())
    assert len(engine.BUFFER) == 0
    assert isolated_engine == []


def test_processa_buffers_vectors_and_stays_silent_while_collecting(isolated_engine):
    feed(4)
    assert len(engine.BUFFER) == 4
    assert engine.TREINADO is False
    assert engine.MODEL.fit_calls == []
    assert isolated_engine == []


def test_processa_trains_exactly_when_the_buffer_is_full(isolated_engine):
    feed(5)
    assert engine.TREINADO is True
    assert engine.MODEL.fit_calls == [(5, 12)]
    # the training packet itself is not scored
    assert isolated_engine == []


def test_processa_alerts_when_the_score_exceeds_the_threshold(isolated_engine, monkeypatch):
    feed(5)
    monkeypatch.setattr(engine, "THRESH", 0.7)
    engine.MODEL.score = 0.95

    engine.processa(packet(src="10.9.9.9"))

    assert isolated_engine == [("Anomalia ML", "10.9.9.9", "score=0.95")]


@pytest.mark.parametrize("score", [0.2, 0.7])
def test_processa_does_not_alert_at_or_below_the_threshold(isolated_engine, monkeypatch, score):
    feed(5)
    monkeypatch.setattr(engine, "THRESH", 0.7)
    engine.MODEL.score = score

    engine.processa(packet())

    assert isolated_engine == []


def test_treina_needs_the_minimum_number_of_samples(isolated_engine):
    for _ in range(4):
        engine.BUFFER.append(np.zeros(12))
    engine.treina()
    assert engine.TREINADO is False
    assert engine.MODEL.fit_calls == []


def test_small_buffer_size_still_allows_training(monkeypatch):
    """Regression: with a buffer under 1000 the old fixed minimum made training impossible."""
    monkeypatch.setenv("CHIMERA_ML_BUFFER_SIZE", "50")
    names = (
        "chimera_ids.base.config",
        "chimera_ids.models.ml_model_config",
        "chimera_ids.rules.ml_detection_engine",
    )
    try:
        for name in names:
            importlib.reload(sys.modules[name])
        reloaded = sys.modules[names[-1]]
        assert reloaded.BUFFER.maxlen == 50
        assert reloaded.MIN_AMOSTRAS_TREINO == 50
    finally:
        monkeypatch.undo()
        for name in names:
            importlib.reload(sys.modules[name])


def test_real_model_scores_an_odd_packet_above_normal_traffic(isolated_engine, monkeypatch):
    """End to end with the real Isolation Forest: train on normal packets, then score."""
    from chimera_ids.models.ml_model_config import MODEL

    rng = np.random.default_rng(0)
    monkeypatch.setattr(engine, "MODEL", MODEL)
    monkeypatch.setattr(engine, "BUFFER", deque(maxlen=1000))
    monkeypatch.setattr(engine, "MIN_AMOSTRAS_TREINO", 1000)

    for i in range(1000):
        pkt = IP(src=f"10.0.{i % 5}.1", dst="10.0.0.2", ttl=64) / TCP(
            sport=int(rng.integers(40000, 40100)), dport=443, flags="A"
        )
        pkt.time = 1000.0 + i * 0.01
        engine.processa(pkt)
    assert engine.TREINADO is True

    normal = IP(src="10.0.1.1", dst="10.0.0.2", ttl=64) / TCP(sport=40050, dport=443, flags="A")
    odd = (
        IP(src="10.6.6.6", dst="10.0.0.2", ttl=1)
        / TCP(sport=1, dport=6667, flags="FPU")
        / Raw(load=bytes(rng.integers(0, 256, 1400, dtype=np.uint8)))
    )
    normal.time = 1011.0
    odd.time = 1011.0

    last_seen_snapshot = vectorizer.last_seen.copy()

    normal_vector = vectorizer.to_vector(normal)
    odd_vector = vectorizer.to_vector(odd)

    normal_score = MODEL.decision_function(normal_vector.reshape(1, -1))[0]
    odd_score = MODEL.decision_function(odd_vector.reshape(1, -1))[0]

    vectorizer.last_seen.clear()
    vectorizer.last_seen.update(last_seen_snapshot)

    assert odd_score > normal_score

    monkeypatch.setattr(engine, "THRESH", (odd_score + normal_score) / 2)

    engine.processa(normal)
    engine.processa(odd)    
