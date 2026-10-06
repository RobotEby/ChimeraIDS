from scapy.all import IP, TCP, UDP


def extrai(p):
    return {
        "ts": p.time,
        "src": p[IP].src,
        "dst": p[IP].dst,
        "proto": p.proto,
        "sport": p.sport if TCP in p or UDP in p else 0,
        "dport": p.dport if TCP in p or UDP in p else 0,
        "len": len(p),
        "flags": str(p[TCP].flags) if TCP in p else "",
    }
