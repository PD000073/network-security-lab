
import hashlib
import logging
import time
import threading

from scapy.config import conf
from scapy.layers.inet import TCP, IP
from scapy.packet import Packet
from scapy.sendrecv import send, sniff
from scapy.compat import raw

from random import randrange

log = logging.getLogger(__name__)

SERVER_IP = '131.159.15.68'
SERVER_PORT = 20102
COOKIE_SECRET = 'TASTY_COOKIES123'
RUN_TIMEOUT_SECONDS = 15

SRC_PORT = randrange(10000, 50000)


def generate_syn_cookie(client_ip: str, client_port: int, server_secret: str):
    hash_input = f'{client_ip}{client_port}{server_secret}'.encode()

    return int(
        hashlib.sha256(hash_input).hexdigest(), 16
    ) % (2**32)


def handle_packet(packet: Packet):

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    # Only process packets coming FROM the challenge server
    if packet[IP].src != SERVER_IP:
        return

    tcp = packet[TCP]

    # Step 2: Server sends SYN-ACK
    if 'S' in tcp.flags and 'A' in tcp.flags:

        print("\n[+] Received SYN-ACK from server")

        print("Server SEQ:", tcp.seq)
        print("Server ACK:", tcp.ack)

        # Step 3: Send our manually constructed ACK
        ack_packet = IP(dst=SERVER_IP) / TCP(
            sport=SRC_PORT,
            dport=SERVER_PORT,
            flags='A',
            seq=tcp.ack,
            ack=tcp.seq + 1
        )

        print("[+] Sending final ACK:")
        ack_packet.show()

        send(ack_packet, verbose=False)

    # Step 4: Server sends the flag
    elif tcp.payload:

        print("\n[+] Server response:")
        print(raw(tcp.payload).decode(errors="replace"))


def start_sniffing():

    sniff(
        filter=f'tcp port {SERVER_PORT}',
        prn=handle_packet,
        store=False,
        iface='eth0',
        timeout=RUN_TIMEOUT_SECONDS,
    )


def main():

    conf.use_pcap = False

    # Start packet sniffer
    server_thread = threading.Thread(
        target=start_sniffing,
        daemon=True
    )

    server_thread.start()

    time.sleep(2)

    # Calculate cookie
    COOKIE = generate_syn_cookie(
        SERVER_IP,
        SERVER_PORT,
        COOKIE_SECRET
    )

    print("[+] Cookie:", COOKIE)
    print("[+] Source port:", SRC_PORT)

    # Step 1: Send initial SYN with cookie as SEQ
    syn_packet = IP(dst=SERVER_IP) / TCP(
        sport=SRC_PORT,
        dport=SERVER_PORT,
        flags='S',
        seq=COOKIE
    )

    print("\n[+] Sending initial SYN:")
    syn_packet.show()

    send(syn_packet, verbose=False)

    # Keep the process alive for a bounded time to collect server responses.
    server_thread.join(timeout=RUN_TIMEOUT_SECONDS)
    print(f"[+] Client finished after {RUN_TIMEOUT_SECONDS}s timeout window")


if __name__ == '__main__':

    logging.basicConfig(level=logging.INFO)

    main()
