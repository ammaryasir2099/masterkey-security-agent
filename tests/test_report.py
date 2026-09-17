import json
from masterkey_agent.report import write_report

def test_write_report_creates_json(tmp_path):
    path=tmp_path/"report.json"; write_report(path,{"ok":True}); assert json.loads(path.read_text(encoding="utf-8"))=={"ok":True}

def test_write_report_wraps_text_data(tmp_path):
    path=tmp_path/"nested"/"report.json"; write_report(path,{"value":1}); assert path.exists()
