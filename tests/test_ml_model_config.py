import importlib

import numpy as np
from pyod.models.iforest import IForest


def test_ml_model_config_imports_without_error():
    """
    Regression test: this module used to do
    `from models.ml_model_config import IForest` (importing from itself),
    which raised an ImportError the moment anything tried to import it.
    """
    module = importlib.import_module("models.ml_model_config")
    assert isinstance(module.MODEL, IForest)
    assert module.BUFFER.maxlen == 10000
    assert module.TREINADO is False
    assert module.THRESH == 0.7


def test_ml_detection_engine_imports_without_starting_capture():
    """
    Regression test: `sniff()` used to run at module level, so importing
    this module for testing would immediately start live packet capture.
    """
    module = importlib.import_module("rules.ml_detection_engine")
    assert callable(module.processa)
    assert callable(module.treina)


def test_treina_fits_the_model_once_enough_samples_are_buffered(monkeypatch):
    module = importlib.import_module("rules.ml_detection_engine")

    # Reset shared module-level state so this test doesn't depend on
    # whatever earlier tests may have buffered.
    module.BUFFER.clear()
    monkeypatch.setattr(module, "TREINADO", False)

    for _ in range(999):
        module.BUFFER.append(np.random.rand(12))
    module.treina()
    assert module.TREINADO is False  # not yet: needs >= 1000 samples

    module.BUFFER.append(np.random.rand(12))
    module.treina()
    assert module.TREINADO is True
