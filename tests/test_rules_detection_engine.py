import pytest
import rules.rules_detection_engine as engine
from base.baseline_dynamic_store import baseline, ddos_ultimo_alerta, syn_counter


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
    baseline["pps_buckets"].clear()
    ddos_ultimo_alerta.clear()
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


class FakeClock:
    def __init__(self, start=1_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    c = FakeClock()
    monkeypatch.setattr(engine.time, "time", c)
    return c


def _steady_traffic(clock, seconds=15, per_second=2):
    for _ in range(seconds):
        for _ in range(per_second):
            engine.detecta(synthetic_packet())
        clock.advance(1)


def test_detecta_does_not_ddos_alert_on_steady_traffic(clock):
    _steady_traffic(clock, seconds=30, per_second=5)
    assert "DDoS" not in alerts_written()


def test_detecta_does_not_ddos_alert_on_many_packets_during_warmup(clock):
    # Plenty of packets, but all inside the first seconds: no baseline yet.
    for _ in range(200):
        engine.detecta(synthetic_packet())
    assert "DDoS" not in alerts_written()


def test_detecta_raises_ddos_alert_on_a_sudden_packet_burst(clock):
    _steady_traffic(clock)
    for _ in range(200):
        engine.detecta(synthetic_packet())

    assert "DDoS" in alerts_written()


def test_detecta_ddos_alerts_once_per_second_not_once_per_packet(clock):
    _steady_traffic(clock)
    for _ in range(500):
        engine.detecta(synthetic_packet())

    assert alerts_written().count("DDoS") == 1


def test_detecta_keeps_alerting_during_a_sustained_flood(clock):
    _steady_traffic(clock)
    for _ in range(20):
        for _ in range(300):
            engine.detecta(synthetic_packet())
        clock.advance(1)

    assert alerts_written().count("DDoS") == 20


def test_detecta_ddos_baselines_are_per_source_ip(clock):
    _steady_traffic(clock)
    for _ in range(200):
        engine.detecta(synthetic_packet(src="10.0.0.9"))

    assert "DDoS" not in alerts_written()


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
