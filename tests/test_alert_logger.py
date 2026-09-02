from base import config
from logs.alert_logger import alerta


def test_alerta_writes_a_line_to_the_configured_log_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    alerta("DDoS", "10.0.0.1")

    with open(config.RULE_ALERT_LOG_PATH) as f:
        content = f.read()

    assert "DDoS" in content
    assert "10.0.0.1" in content


def test_alerta_includes_optional_detail_field(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    alerta("Anomalia ML", "10.0.0.1", detalhe="score=0.85")

    with open(config.RULE_ALERT_LOG_PATH) as f:
        content = f.read()

    assert "score=0.85" in content


def test_alerta_appends_rather_than_overwrites(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    alerta("DDoS", "10.0.0.1")
    alerta("PortScan", "10.0.0.2")

    with open(config.RULE_ALERT_LOG_PATH) as f:
        lines = f.readlines()

    assert len(lines) == 2
