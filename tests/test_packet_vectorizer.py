import features.packet_vectorizer as vectorizer
import pytest
from scapy.all import IP, TCP, UDP, Raw


def test_entropy_of_empty_bytes_is_zero():
    assert vectorizer.entropy(b"") == 0.0


def test_entropy_of_repeated_byte_is_zero():
    # A payload made of a single repeated byte has zero information entropy.
    assert vectorizer.entropy(b"\x00" * 32) == 0.0


def test_entropy_of_varied_bytes_is_positive():
    assert vectorizer.entropy(bytes(range(64))) > 0.0


def test_to_vector_returns_12_dimensional_array():
    vectorizer.last_seen.clear()
    pkt = IP(src="10.0.0.1", dst="10.0.0.2", ttl=64) / TCP(sport=1234, dport=80, flags="S")
    vec = vectorizer.to_vector(pkt)
    assert vec.shape == (12,)


def test_to_vector_captures_basic_tcp_fields():
    vectorizer.last_seen.clear()
    pkt = IP(src="10.0.0.1", dst="10.0.0.2", ttl=64) / TCP(sport=1234, dport=80, flags="S")
    vec = vectorizer.to_vector(pkt)

    assert vec[2] == 1234  # source port
    assert vec[3] == 80  # destination port
    assert vec[6] == 64  # TTL


def test_to_vector_handles_udp_packets_without_tcp_flags():
    vectorizer.last_seen.clear()
    pkt = IP(src="10.0.0.1", dst="10.0.0.2", ttl=32) / UDP(sport=5000, dport=53)
    vec = vectorizer.to_vector(pkt)

    assert vec[2] == 5000
    assert vec[3] == 53
    assert vec[4] == 0  # no TCP flags on a UDP packet


def test_to_vector_reflects_payload_length_and_entropy():
    vectorizer.last_seen.clear()
    payload = bytes(range(64))
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2) / Raw(load=payload)
    vec = vectorizer.to_vector(pkt)

    assert vec[8] == len(payload)
    assert vec[10] > 0.0


def test_to_vector_raises_a_clear_error_for_a_non_ip_packet():
    from scapy.all import Ether

    with pytest.raises(ValueError, match="IP layer"):
        vectorizer.to_vector(Ether())
