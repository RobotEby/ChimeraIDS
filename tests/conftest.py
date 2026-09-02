import os
import sys

# The codebase uses absolute imports rooted at src/main (e.g.
# `from base.baseline_dynamic_store import ...`), matching how the modules
# are actually run (`python src/main/examples/mini_ids.py`, etc.). Add that
# directory to sys.path so tests can import the same way.
SRC_MAIN = os.path.join(os.path.dirname(__file__), "..", "src", "main")
sys.path.insert(0, os.path.abspath(SRC_MAIN))
