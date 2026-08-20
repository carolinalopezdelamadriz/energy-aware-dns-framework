# Makes the flat src/ package importable as `import cfp`, `import browser`,
# etc. from the test files, the same way main.py sees it when run directly
# (python3 src/main.py puts src/ on sys.path automatically; pytest doesn't).
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
