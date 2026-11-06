"""Length-prefixed TCP framing so messages of any size arrive intact."""
import struct


def send_msg(sock, data: bytes) -> None:
    sock.sendall(struct.pack(">Q", len(data)) + data)


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed by peer")
        buf += chunk
    return buf


def recv_msg(sock) -> bytes:
    (length,) = struct.unpack(">Q", _recv_exact(sock, 8))
    return _recv_exact(sock, length)
