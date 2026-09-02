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

import time

from base import config
from base.baseline_dynamic_store import baseline, calc_stats, corta, syn_counter
from logs.alert_logger import alerta

DDoS_DESVIOS = config.DDOS_DESVIOS
SYN_FLOOD_LIMITE = config.SYN_FLOOD_LIMITE
PORT_SCAN_LIMIAR = config.PORT_SCAN_LIMIAR
JANELA_SEGUNDOS = config.JANELA_BASELINE_SEGUNDOS
MIN_AMOSTRAS_BASELINE = config.MIN_AMOSTRAS_BASELINE


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

    # DDoS test: current packets-per-window vs. the running mean/stdev of
    # the per-packet contributions in that same window. Skipped until there
    # is a minimally meaningful baseline (see module docstring, point 1).
    if len(pps) >= MIN_AMOSTRAS_BASELINE:
        mu_pps, sigma_pps = calc_stats(pps)
        if len(pps) > mu_pps + DDoS_DESVIOS * sigma_pps:
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
