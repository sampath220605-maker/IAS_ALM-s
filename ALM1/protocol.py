"""Tiny framing protocol: [4B header-len][8B payload-len][JSON header][payload bytes]."""
import json
import struct
import hashlib

HOST, PORT = "127.0.0.1", 5000
ALGOS = {1: "Caesar Cipher", 2: "Playfair Cipher", 3: "SDES"}


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            raise ConnectionError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


def send_frame(sock, header: dict, payload: bytes = b""):
    h = json.dumps(header).encode()
    sock.sendall(struct.pack("!IQ", len(h), len(payload)) + h + payload)


def recv_frame(sock):
    hl, pl = struct.unpack("!IQ", recv_exact(sock, 12))
    header = json.loads(recv_exact(sock, hl))
    return header, recv_exact(sock, pl)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hex_preview(data: bytes, n=48):
    s = data[:n].hex(' ')
    return s + (" ..." if len(data) > n else "")


def text_preview(data: bytes, n=200):
    s = data[:n].decode("utf-8", errors="replace")
    return s + (" ..." if len(data) > n else "")
