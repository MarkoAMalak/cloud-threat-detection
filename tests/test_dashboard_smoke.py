from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parents[1] / "app" / "streamlit_app.py"


def test_dashboard_file_exists():
    assert APP.exists()


def test_dashboard_renders_without_errors():
    at = AppTest.from_file(str(APP), default_timeout=120).run()
    assert not at.exception, [e.value for e in at.exception]
    assert len(at.metric) > 0
    assert len(at.dataframe) > 0
