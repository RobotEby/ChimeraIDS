from scapy.all import sniff


def captura(pacote):
    # every package that arrives goes here
    print(pacote.summary())


def main():
    # IPv4 only, without saving to RAM
    sniff(prn=captura, store=False, filter="ip")
    # If you change the offline capture, replace sniff with rdpcap("dump.pcap").


if __name__ == "__main__":
    main()
