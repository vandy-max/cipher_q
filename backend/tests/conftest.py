import os
import sys

# Allow `import intent`, `import database`, etc. when running pytest
# from the backend/ directory or from the repo root.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)
