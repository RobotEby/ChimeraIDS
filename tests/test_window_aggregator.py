import pytest
import windows.traffic_window_aggregator as aggregator
from scapy.all import IP, TCP


@pytest.fixture(autouse=True)
def reset_state(monkeypatch, tmp_path):
    aggregator.buckets.clear()
    aggregator.flow_bytes_history.clear()
    monkeypatch.chdir(tmp_path)
    yield


def make_syn_packets(n, src="10.0.0.1", dst="10.0.0.2", dport=80):
    return [
        IP(src=src, dst=dst, ttl=64) / TCP(sport=1234, dport=dport, flags="S") for _ in range(n)
    ]


def test_pacotes2vetor_of_empty_list_is_all_zeros():
    vec = aggregator.pacotes2vetor([])
    assert list(vec) == [0.0] * 12


def test_pacotes2vetor_counts_packets_and_bytes():
    pkts = make_syn_packets(5)
    vec = aggregator.pacotes2vetor(pkts)

    assert vec[1] == 5  # total_pkts
    assert vec[0] == sum(len(p) for p in pkts)  # total_bytes
    assert vec[2] == 1  # a single unique source IP
    assert vec[8] == 5  # all 5 are SYN packets


def test_processa_vetor_does_not_alert_during_the_learning_period():
    flow_key = (6, "10.0.0.1", "10.0.0.2", 80)

    for slot in range(3):
        vec = aggregator.pacotes2vetor(make_syn_packets(5))
        alertou = aggregator.processa_vetor(vec, flow_key, slot)
        assert alertou is False


def test_processa_vetor_detects_a_sudden_volume_spike_after_learning():
    flow_key = (6, "10.0.0.1", "10.0.0.2", 80)

    # Build up a steady baseline of small windows.
    for slot in range(6):
        vec = aggregator.pacotes2vetor(make_syn_packets(5))
        aggregator.processa_vetor(vec, flow_key, slot)

    # A window with a large volume spike should now trigger an alert.
    spike_vec = aggregator.pacotes2vetor(make_syn_packets(200))
    alertou = aggregator.processa_vetor(spike_vec, flow_key, 99)

    assert alertou is True
    with open("alerts.log") as f:
        assert "FlowAnomaly" in f.read()


def test_processa_vetor_keeps_separate_baselines_per_flow():
    flow_a = (6, "10.0.0.1", "10.0.0.2", 80)
    flow_b = (6, "10.0.0.3", "10.0.0.4", 443)

    for slot in range(6):
        aggregator.processa_vetor(aggregator.pacotes2vetor(make_syn_packets(5)), flow_a, slot)
        aggregator.processa_vetor(aggregator.pacotes2vetor(make_syn_packets(5)), flow_b, slot)

    # A spike on flow_a should not be affected by flow_b's independent history.
    spike = aggregator.pacotes2vetor(make_syn_packets(200))
    assert aggregator.processa_vetor(spike, flow_a, 99) is True
    assert len(aggregator.flow_bytes_history[flow_b]) == 6


def test_chave_groups_by_proto_src_dst_port():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)
    assert aggregator.chave(pkt) == (6, "10.0.0.1", "10.0.0.2", 80)


def test_arredonda_rounds_down_to_window_boundary():
    assert aggregator.arredonda(12.9) == 10.0
    assert aggregator.arredonda(9.9) == 5.0
