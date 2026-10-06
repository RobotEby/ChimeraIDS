"""
Temporal flow aggregation (5-second windows).

Groups packets into 5-second windows keyed by (proto, src_ip, dst_ip,
dst_port), compresses each window into a 12-dimensional summary vector, and
compares each flow's window-over-window byte/packet volume against that
flow's own trailing baseline to catch slow, low-and-slow, or distributed
attacks that per-packet rules can miss.

Previously this module (and a byte-for-byte duplicate,
`traffic-window-aggregator.py`, whose filename wasn't even a valid Python
module name) imported `processa_vetor` from itself; that name was never
defined anywhere in the codebase, so importing this module raised an
ImportError and the feature could not run at all. The duplicate file has
been removed and `processa_vetor` is now implemented for real below.

NOTE on the detection approach: the aggregated window vector's 12 fields
(total_bytes, total_pkts, unique source IPs, etc.) describe a *window*, not
a single packet — they are not the same feature space as
`features.packet_vectorizer.to_vector`'s per-packet vector, even though
both happen to be 12-dimensional. Feeding this vector into the
already-trained per-packet Isolation Forest model in
`models.ml_model_config` would silently produce meaningless scores. Instead,
this module tracks a simple, real per-flow baseline (mean/stdev of total
bytes per window) and alerts on a >3-stdev deviation, mirroring the same
statistical approach used in `rules.rules_detection_engine`.
"""

from collections import defaultdict, deque

import numpy as np
from scapy.all import IP, TCP, UDP, Raw

from chimera_ids.base import config
from chimera_ids.features.packet_vectorizer import entropy
from chimera_ids.logs.alert_logger import alerta

JANELA = config.JANELA_AGREGACAO_SEGUNDOS

# How many past windows to keep per flow for the baseline, and how many
# windows must be observed before we start alerting (a short learning
# period, same idea as the rule-based engine's warm-up window).
HISTORICO_JANELAS = config.HISTORICO_JANELAS
MIN_JANELAS_PARA_ALERTA = config.MIN_JANELAS_PARA_ALERTA
DESVIOS_PARA_ALERTA = config.DESVIOS_PARA_ALERTA_FLUXO

buckets = defaultdict(lambda: defaultdict(list))

# Per-flow history of total_bytes across recent windows, for the baseline.
flow_bytes_history = defaultdict(lambda: deque(maxlen=HISTORICO_JANELAS))

# [0]  total_bytes
# [1]  total_pkts
# [2]  uniq_src_ips
# [3]  uniq_dst_ports
# [4]  avg_pkt_len
# [5]  std_pkt_len
# [6]  avg_ttl
# [7]  proto_major  # 0=ICMP, 6=TCP, 17=UDP, outro=-1
# [8]  tcp_syn_cnt
# [9]  tcp_ack_cnt
# [10] tcp_psh_cnt
# [11] entropy_payload average of packages
# Function that compresses the list of packages into 1 vector:


def pacotes2vetor(pacotes):
    if not pacotes:
        return np.zeros(12)
    bytes_total = sum(len(p) for p in pacotes)
    pkts = len(pacotes)
    src_ips = {p[IP].src for p in pacotes}
    dst_ports = {p.dport if TCP in p or UDP in p else 0 for p in pacotes}
    lens = [len(p) for p in pacotes]
    ttls = [p[IP].ttl for p in pacotes]
    protos = {p[IP].proto for p in pacotes}
    syn = ack = psh = 0
    entropies = []
    for p in pacotes:
        if TCP in p:
            f = int(p[TCP].flags)
            syn += bool(f & 0x02)
            ack += bool(f & 0x10)
            psh += bool(f & 0x08)
        entropies.append(entropy(bytes(p[Raw]) if p.haslayer(Raw) else b""))

    v = np.zeros(12)
    v[0] = bytes_total
    v[1] = pkts
    v[2] = len(src_ips)
    v[3] = len(dst_ports)
    v[4] = np.mean(lens)
    v[5] = np.std(lens)
    v[6] = np.mean(ttls)
    v[7] = next(iter(protos)) if len(protos) == 1 else -1
    v[8] = syn
    v[9] = ack
    v[10] = psh
    v[11] = np.mean(entropies) if entropies else 0
    return v


def processa_vetor(vetor, fluxo_key, slot):
    """
    Compare this window's total-bytes volume for `fluxo_key` against that
    flow's own trailing history, and alert on a large deviation.

    Returns True if an alert was raised, False otherwise (useful for tests
    without needing to parse the log file).
    """
    total_bytes = float(vetor[0])
    historico = flow_bytes_history[fluxo_key]

    alertou = False
    if len(historico) >= MIN_JANELAS_PARA_ALERTA:
        media = float(np.mean(historico))
        desvio = float(np.std(historico))
        if total_bytes > media + DESVIOS_PARA_ALERTA * desvio:
            proto, src_ip, dst_ip, dst_port = fluxo_key
            alerta(
                "FlowAnomaly",
                f"{src_ip}->{dst_ip}:{dst_port} (proto={proto}, janela={slot})",
            )
            alertou = True

    historico.append(total_bytes)
    return alertou


# Calculate flow key.
# Store packet in bucket[slot][key].
# When the clock exceeds slot + WINDOW, convert that bucket to a vector,
# send it to the model, then delete it.


def arredonda(ts):
    return int(ts / JANELA) * JANELA


def chave(p):
    ip = p[IP]
    return (ip.proto, ip.src, ip.dst, ip.dport if TCP in p or UDP in p else 0)


def fecha_slot(slot):
    if slot not in buckets:
        return
    for fluxo_key, pacotes in buckets[slot].items():
        vet = pacotes2vetor(pacotes)
        processa_vetor(vet, fluxo_key, slot)
    del buckets[slot]
