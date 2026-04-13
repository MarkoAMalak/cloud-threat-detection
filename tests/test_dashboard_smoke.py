from pathlib import Path

def test_dashboard_file_exists():
    assert Path("app/streamlit_app.py").exists()
