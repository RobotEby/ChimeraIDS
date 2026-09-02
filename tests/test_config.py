import importlib

from base import config


def test_defaults_match_original_hardcoded_values():
    assert config.DDOS_DESVIOS == 3.0
    assert config.SYN_FLOOD_LIMITE == 100
    assert config.PORT_SCAN_LIMIAR == 15
    assert config.JANELA_AGREGACAO_SEGUNDOS == 5.0
    assert config.ML_BUFFER_SIZE == 10000
    assert config.ML_THRESHOLD == 0.7


def test_environment_variable_overrides_an_int_setting(monkeypatch):
    monkeypatch.setenv("CHIMERA_SYN_FLOOD_LIMITE", "50")
    reloaded = importlib.reload(config)
    try:
        assert reloaded.SYN_FLOOD_LIMITE == 50
    finally:
        monkeypatch.delenv("CHIMERA_SYN_FLOOD_LIMITE", raising=False)
        importlib.reload(config)


def test_environment_variable_overrides_a_float_setting(monkeypatch):
    monkeypatch.setenv("CHIMERA_DDOS_DESVIOS", "4.5")
    reloaded = importlib.reload(config)
    try:
        assert reloaded.DDOS_DESVIOS == 4.5
    finally:
        monkeypatch.delenv("CHIMERA_DDOS_DESVIOS", raising=False)
        importlib.reload(config)
