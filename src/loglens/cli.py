"""Command line entry point for `uv run app`: starts the LogLens Streamlit app.

Extra arguments are passed to Streamlit, e.g. `uv run app --server.port 8600`.
"""
import sys
from pathlib import Path

from streamlit.web import cli as stcli

APP_PATH = Path(__file__).parent / "ui" / "app.py"


def main() -> None:
    sys.argv = ["streamlit", "run", str(APP_PATH), *sys.argv[1:]]
    sys.exit(stcli.main())
