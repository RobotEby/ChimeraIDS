from scapy.all import IP, TCP, UDP

from chimera_ids.features.packet_feature_extractor import extrai


def test_extrai_describes_a_tcp_packet():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")

    feature = extrai(pkt)

    assert feature["src"] == "10.0.0.1"
    assert feature["dst"] == "10.0.0.2"
    assert feature["sport"] == 1234
    assert feature["dport"] == 80
    assert feature["flags"] == "S"
    assert feature["len"] == len(pkt)
    assert feature["ts"] == pkt.time


def test_extrai_describes_a_udp_packet_without_flags():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53)

    feature = extrai(pkt)

    assert feature["sport"] == 5000
    assert feature["dport"] == 53
    assert feature["flags"] == ""


def test_extrai_uses_zero_ports_for_packets_without_tcp_or_udp():
    feature = extrai(IP(src="10.0.0.1", dst="10.0.0.2", proto=1))

    assert feature["sport"] == 0
    assert feature["dport"] == 0
    assert feature["flags"] == ""
