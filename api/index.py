from pathlib import Path
import sys

backend_path = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(backend_path))

from ecdat.api.app import app

__all__ = ["app"]
