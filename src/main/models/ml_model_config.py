from collections import deque

from base import config
from pyod.models.iforest import IForest

MODEL = IForest(
    n_estimators=config.ML_N_ESTIMATORS,
    contamination=config.ML_CONTAMINATION,
    behaviour="new",
)
BUFFER = deque(maxlen=config.ML_BUFFER_SIZE)
TREINADO = False
# score > THRESH becomes an alert
THRESH = config.ML_THRESHOLD
