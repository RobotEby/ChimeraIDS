import numpy as np
from scapy.all import IP, TCP, UDP, Raw

# ip -> timestamp
last_seen = {}


def entropy(b):
    if not b:
        return 0.0
    # Only the first 64 bytes are inspected, so probabilities must be relative
    # to that sample. Dividing by len(b) understated the entropy of any payload
    # longer than 64 bytes (the probabilities no longer summed to 1).
    sample = b[:64]
    freq = np.bincount(np.frombuffer(sample, dtype=np.uint8))
    pk = freq[freq > 0] / len(sample)
    return -np.sum(pk * np.log2(pk))


def to_vector(p):
    global last_seen
    if IP not in p:
        raise ValueError("to_vector() requires a packet with an IP layer")
    ip = p[IP]
    ts = p.time
    vec = np.zeros(12)
    vec[0] = len(p)
    vec[1] = ip.proto
    vec[2] = p.sport if TCP in p or UDP in p else 0
    vec[3] = p.dport if TCP in p or UDP in p else 0
    vec[4] = int(p[TCP].flags) if TCP in p else 0
    vec[5] = p[TCP].window if TCP in p else 0
    vec[6] = ip.ttl
    vec[7] = ip.id
    vec[8] = len(p[Raw]) if p.haslayer(Raw) else 0
    vec[9] = 0.0 if ip.src not in last_seen else (ts - last_seen[ip.src]) * 1e6
    vec[10] = entropy(bytes(p[Raw]) if p.haslayer(Raw) else b"")
    vec[11] = sum(1 for t in last_seen.values() if ts - t < 5)
    last_seen[ip.src] = ts
    return vec
