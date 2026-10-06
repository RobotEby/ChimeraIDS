import os
import sys

# Make `import chimera_ids` work without installing the package (CI and local
# runs also work with `pip install -e ".[dev]"`; this just removes the need).
SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, os.path.abspath(SRC))
