from collections import deque

from pyod.models.iforest import IForest

from chimera_ids.base import config

MODEL = IForest(
    n_estimators=config.ML_N_ESTIMATORS,
    contamination=config.ML_CONTAMINATION,
    behaviour="new",
)
BUFFER = deque(maxlen=config.ML_BUFFER_SIZE)
TREINADO = False
# score > THRESH becomes an alert
THRESH = config.ML_THRESHOLD
