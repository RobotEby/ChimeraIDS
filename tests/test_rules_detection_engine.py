import pytest
import rules.rules_detection_engine as engine
from base.baseline_dynamic_store import baseline, syn_counter


@pytest.fixture(autouse=True)
def reset_state(monkeypatch, tmp_path):
    """
    Isolate each test from the module-level mutable state (the baseline
    dicts are shared across the whole process, same as they would be across
    a real capture session) and redirect the alert log to a temp file
    instead of writing into the working directory.
    """
    baseline["pps"].clear()
    baseline["bps"].clear()
    baseline["uniq"].clear()
    syn_counter.clear()

    monkeypatch.chdir(tmp_path)
    yield


def synthetic_packet(src="10.0.0.1", dst="10.0.0.2", length=60, dport=80, flags=""):
    return {"src": src, "dst": dst, "len": length, "dport": dport, "flags": flags}


def alerts_written():
    try:
        with open("alerts.log") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def test_detecta_does_not_alert_on_a_single_normal_packet():
    engine.detecta(synthetic_packet())
    assert alerts_written() == ""


def test_detecta_raises_ddos_alert_on_a_sudden_packet_burst():
    # A handful of steady packets to build up a small baseline...
    for _ in range(5):
        engine.detecta(synthetic_packet())
    # ...then a sudden burst from the same source IP.
    for _ in range(50):
        engine.detecta(synthetic_packet())

    assert "DDoS" in alerts_written()


def test_detecta_raises_port_scan_alert_on_many_unique_ports():
    for port in range(1, 30):
        engine.detecta(synthetic_packet(dport=port))

    assert "PortScan" in alerts_written()


def test_detecta_raises_syn_flood_alert_after_threshold_consecutive_syns():
    for _ in range(101):
        engine.detecta(synthetic_packet(flags="S"))

    assert "SYN-Flood" in alerts_written()


def test_detecta_resets_syn_counter_on_ack():
    for _ in range(90):
        engine.detecta(synthetic_packet(flags="S"))
    engine.detecta(synthetic_packet(flags="A"))

    assert syn_counter["10.0.0.1"] == 0
