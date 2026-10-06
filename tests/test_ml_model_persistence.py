import signal

import joblib
import pytest
from pyod.models.iforest import IForest

import chimera_ids.models.ml_model_persistence as persistence


def test_salva_writes_a_loadable_model_to_the_given_path(tmp_path):
    destino = tmp_path / "model.pkl"

    caminho = persistence.salva(caminho=str(destino))

    assert caminho == str(destino)
    assert destino.exists()
    assert isinstance(joblib.load(destino), IForest)


def test_salva_defaults_to_the_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    persistence.salva()
    assert (tmp_path / persistence.CAMINHO_PADRAO).exists()


def test_carrega_roundtrips_what_salva_wrote(tmp_path):
    destino = str(tmp_path / "model.pkl")
    persistence.salva(caminho=destino)
    assert isinstance(persistence.carrega(destino), IForest)


def test_salva_can_be_called_as_a_signal_handler(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    persistence.salva(signal.SIGTERM, None)
    assert (tmp_path / persistence.CAMINHO_PADRAO).exists()


@pytest.mark.skipif(not hasattr(signal, "SIGUSR1"), reason="platform has no SIGUSR1")
def test_instala_handler_registers_salva_for_sigusr1():
    anterior = signal.getsignal(signal.SIGUSR1)
    try:
        assert persistence.instala_handler_de_salvamento() is True
        assert signal.getsignal(signal.SIGUSR1) is persistence.salva
    finally:
        signal.signal(signal.SIGUSR1, anterior)


def test_instala_handler_is_a_noop_without_sigusr1(monkeypatch):
    """Windows has no SIGUSR1: installing must not crash."""
    monkeypatch.delattr(persistence.signal, "SIGUSR1", raising=False)
    assert persistence.instala_handler_de_salvamento() is False
