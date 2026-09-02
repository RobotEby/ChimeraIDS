#!/usr/bin/env python3
import statistics
import time
from collections import defaultdict, deque

from scapy.all import IP, TCP, UDP, sniff

WINDOW = 60
# deviations to consider anomalous
THRESHOLD = 3
# SYN threshold
SYN_MAX = 100

baseline_pps = defaultdict(deque)
baseline_bps = defaultdict(deque)
baseline_uniq = defaultdict(set)
syn_counter = defaultdict(int)
learn_mode = True
start = time.time()


def corta(dq, limite):
    while dq and dq[0][0] < limite:
        dq.popleft()


def calc_stats(dq):
    vals = [v for _, v in dq]
    return (statistics.mean(vals), statistics.stdev(vals)) if len(vals) > 1 else (0, 0)


def alerta(tipo, ip):
    t = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[ALERTA] {t} {tipo} origem={ip}")
    with open("alerts.log", "a") as f:
        f.write(f"{time.time()} {tipo} {ip}\n")


def processa(p):
    global learn_mode
    if not p.haslayer(IP):
        return
    f = {
        "ts": p.time,
        "src": p[IP].src,
        "dst": p[IP].dst,
        "len": len(p),
        "dport": p.dport if TCP in p or UDP in p else 0,
        "flags": str(p[TCP].flags) if TCP in p else "",
    }
    ip = f["src"]
    agora = time.time()

    baseline_pps[ip].append((agora, 1))
    baseline_bps[ip].append((agora, f["len"]))
    baseline_uniq[ip].add(f["dport"])
    corta(baseline_pps[ip], agora - WINDOW)
    corta(baseline_bps[ip], agora - WINDOW)

    if learn_mode and agora - start > WINDOW:
        learn_mode = False
        print("-- Aprendizado encerrado. IDS ativo --")

    if not learn_mode:
        μ_pps, σ_pps = calc_stats(baseline_pps[ip])
        μ_uniq = len(baseline_uniq[ip]) - 1 if len(baseline_uniq[ip]) > 1 else 0
        σ_uniq = 2
        if len(baseline_pps[ip]) > μ_pps + THRESHOLD * σ_pps:
            alerta("DDoS", ip)
        if len(baseline_uniq[ip]) > μ_uniq + THRESHOLD * σ_uniq:
            alerta("PortScan", ip)
        if f["flags"] == "S":
            syn_counter[ip] += 1
        elif "A" in f["flags"]:
            syn_counter[ip] = 0
        if syn_counter[ip] > SYN_MAX:
            alerta("SYN-Flood", ip)


def main():
    print("Capturando... Ctrl-C para parar.")
    sniff(prn=processa, store=False, filter="ip")


if __name__ == "__main__":
    main()
