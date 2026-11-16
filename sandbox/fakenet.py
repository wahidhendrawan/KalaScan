"""Loopback stand-in for the internet inside the KalaScan sandbox.

The container has no network (`--network none`), so a sample that waits for
its server shows nothing. This answers every DNS query with 127.0.0.1 and
accepts TCP on the usual web ports, so the sample goes on to say where it
wanted to connect and what it wanted to send. Nothing leaves the container.

One line per contact goes to the log file named in argv[1]:
    DNS <name>
    HTTP <method> <host> <path>
    TLS <server name>
    TCP <port>

KalaScan embeds this file and hands it to the container; the image only
needs python3.
"""

import socket
import struct
import sys
import threading

LOG = open(sys.argv[1], "a", buffering=1)
LOCK = threading.Lock()
TCP_PORTS = (80, 443, 8000, 8080, 8443)


def log(*parts):
    # The sample chooses these strings: one line, printable ASCII, bounded.
    clean = " ".join("".join(c for c in str(p) if 33 <= ord(c) < 127)[:200] for p in parts)
    with LOCK:
        LOG.write(clean + "\n")


def dns_name(packet):
    labels, i = [], 12
    while i < len(packet) and packet[i]:
        size = packet[i]
        labels.append(packet[i + 1 : i + 1 + size].decode("ascii", "replace"))
        i += 1 + size
    return ".".join(labels), i + 1


def serve_dns():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 53))
    while True:
        try:
            packet, peer = sock.recvfrom(512)
            name, end = dns_name(packet)
            qtype = struct.unpack("!H", packet[end : end + 2])[0]
            log("DNS", name)
            question = packet[12 : end + 4]
            # A queries get 127.0.0.1; anything else an empty answer.
            answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01" if qtype == 1 else b""
            header = packet[:2] + b"\x81\x80\x00\x01" + (b"\x00\x01" if answer else b"\x00\x00") + b"\x00\x00\x00\x00"
            sock.sendto(header + question + answer, peer)
        except Exception:
            continue


def tls_server_name(hello):
    """The SNI host name of a TLS ClientHello, or None."""
    try:
        i = 43  # record header, handshake header, version, random
        i += 1 + hello[i]  # session id
        i += 2 + struct.unpack("!H", hello[i : i + 2])[0]  # cipher suites
        i += 1 + hello[i]  # compression methods
        end = i + 2 + struct.unpack("!H", hello[i : i + 2])[0]
        i += 2
        while i + 4 <= end:
            kind, size = struct.unpack("!HH", hello[i : i + 4])
            if kind == 0:
                return hello[i + 9 : i + 4 + size].decode("ascii", "replace")
            i += 4 + size
    except (IndexError, struct.error):
        pass
    return None


def handle(conn, port):
    try:
        conn.settimeout(2)
        data = conn.recv(4096)
        if data[:1] == b"\x16":
            log("TLS", tls_server_name(data) or "port-%d" % port)
            return
        head = data.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
        request = head[0].split(" ")
        if len(request) == 3 and request[2].startswith("HTTP/"):
            host = next((h.split(":", 1)[1].strip() for h in head[1:] if h.lower().startswith("host:")), "port-%d" % port)
            log("HTTP", request[0], host, request[1])
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        else:
            log("TCP", port)
    except Exception:
        log("TCP", port)
    finally:
        conn.close()


def serve_tcp(port):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(16)
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=handle, args=(conn, port), daemon=True).start()


for target, args in [(serve_dns, ())] + [(serve_tcp, (p,)) for p in TCP_PORTS]:
    threading.Thread(target=target, args=args, daemon=True).start()
open(sys.argv[1] + ".ready", "w").close()
threading.Event().wait()
