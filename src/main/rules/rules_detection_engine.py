"""
Modular, rule-based detection engine.

Consumes a feature dict (see `features.packet_feature_extractor.extrai`),
updates the shared dynamic baseline for the packet's source IP, and raises
an alert (via `logs.alert_logger.alerta`) when a metric exceeds
mean + 3*stdev over the trailing 60-second window, or when a source IP
sends more than 100 consecutive SYNs without an intervening ACK.

Previously this module imported `pps`, `bps`, `uniq`, `syn_counter`,
`μ_pps`, `σ_pps`, `μ_uniq`, `σ_uniq` from itself, none of which were ever
defined anywhere in the codebase — importing this module raised an
ImportError. It also imported `corta` from `examples.mini_ids`, an example
script that should not be a dependency of production detection logic. Both
issues are fixed by using the shared `base.baseline_dynamic_store`.

Two further, previously-untested bugs were found and fixed once the module
could actually run:

1. DDoS check false-positived on literally the first packet from any
   source IP: with 0 or 1 samples, `calc_stats` returns (mean=0, stdev=0),
   so `len(pps) > 0 + 3*0` is trivially true. A minimum-sample warm-up gate
   (`MIN_AMOSTRAS_BASELINE`) is now required before this check runs, mirroring
   the learning-period pattern already used elsewhere in this codebase
   (the ML engine's 10,000-sample training buffer; the window aggregator's
   `MIN_JANELAS_PARA_ALERTA`).

2. Port scan detection could never fire, for any input: the inherited
   heuristic set `mu_uniq = len(uniq) - 1` and `sigma_uniq = 2`, so the
   condition `len(uniq) > mu_uniq + 3*sigma_uniq` reduces to
   `len(uniq) > len(uniq) + 5`, which is false for every possible value of
   `len(uniq)`. It also used an unbounded, never-time-trimmed set, so even a
   fixed detection formula would have kept comparing against
   ever-growing lifetime port counts rather than recent behavior. This is
   replaced with a simple, explicit threshold (a source IP contacting more
   than `PORT_SCAN_LIMIAR` distinct destination ports within the trailing
   60-second window) instead of a statistical mean/stdev comparison — the
   same kind of fixed-threshold approach already used for SYN-flood
   detection below, and a well-established, real port-scan heuristic.
"""

import statistics
import time

from base import config
from base.baseline_dynamic_store import baseline, corta, ddos_ultimo_alerta, syn_counter
from logs.alert_logger import alerta

DDoS_DESVIOS = config.DDOS_DESVIOS
SYN_FLOOD_LIMITE = config.SYN_FLOOD_LIMITE
PORT_SCAN_LIMIAR = config.PORT_SCAN_LIMIAR
JANELA_SEGUNDOS = config.JANELA_BASELINE_SEGUNDOS
MIN_AMOSTRAS_BASELINE = config.MIN_AMOSTRAS_BASELINE
DDOS_PPS_MINIMO = config.DDOS_PPS_MINIMO


def _ddos(ip, agora):
    """Update the per-second packet buckets for `ip`; return True on a DDoS burst.

    Earlier versions compared `len(pps)` with mean/stdev of a series whose
    values were all 1 (mean=1, stdev=0), so any IP with >= MIN samples in the
    window alerted. Here the series is packets-per-second: the current second
    is compared against the *previous* complete seconds (zeros included for
    silent seconds). Seconds already flagged are excluded from the baseline so
    a sustained flood does not teach the baseline that it is normal. A
    floor (`DDOS_PPS_MINIMO`) avoids alerting on tiny absolute rates when the
    history is very flat.
    """
    sec = int(agora)
    buckets = baseline["pps_buckets"][ip]
    if buckets and buckets[-1][0] == sec:
        buckets[-1][1] += 1
    else:
        buckets.append([sec, 1, False])
    corta_buckets = sec - int(JANELA_SEGUNDOS)
    while buckets and buckets[0][0] < corta_buckets:
        buckets.popleft()

    atual = buckets[-1]
    inicio = max(buckets[0][0], corta_buckets)
    por_segundo = {b[0]: b[1] for b in buckets if b[0] < sec and not b[2]}
    flagged = {b[0] for b in buckets if b[0] < sec and b[2]}
    historico = [por_segundo.get(s, 0) for s in range(inicio, sec) if s not in flagged]
    if len(historico) < MIN_AMOSTRAS_BASELINE:
        return False

    mu = statistics.mean(historico)
    sigma = statistics.stdev(historico) if len(historico) > 1 else 0.0
    limite = max(mu + DDoS_DESVIOS * sigma, DDOS_PPS_MINIMO)
    if atual[1] <= limite:
        return False

    atual[2] = True
    if ddos_ultimo_alerta.get(ip) == sec:
        return False
    ddos_ultimo_alerta[ip] = sec
    return True


def detecta(f):
    ip = f["src"]
    agora = time.time()

    pps = baseline["pps"][ip]
    bps = baseline["bps"][ip]
    uniq = baseline["uniq"][ip]

    # updates counters
    pps.append((agora, 1))
    bps.append((agora, f["len"]))
    uniq.append((agora, f["dport"]))

    # clear sliding window (last 60 seconds)
    corta(pps, agora - JANELA_SEGUNDOS)
    corta(bps, agora - JANELA_SEGUNDOS)
    corta(uniq, agora - JANELA_SEGUNDOS)

    # DDoS test: packets in the current 1-second bucket vs. mean + k*stdev
    # of the packets-per-second history of the same source IP.
    if _ddos(ip, agora):
        alerta("DDoS", ip)

    # Port scan test: a fixed threshold on distinct destination ports
    # contacted within the trailing window (see module docstring, point 2,
    # for why the original mean/stdev-based formula could never fire).
    unique_ports = {port for _, port in uniq}
    if len(unique_ports) > PORT_SCAN_LIMIAR:
        alerta("PortScan", ip)

    # SYN flood test
    if f["flags"] == "S":
        syn_counter[ip] += 1
    elif "A" in f["flags"]:
        syn_counter[ip] = 0
    if syn_counter[ip] > SYN_FLOOD_LIMITE:
        alerta("SYN-Flood", ip)
