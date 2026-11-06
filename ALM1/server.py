"""ALM-1 server. Run first:  python server.py"""
import os
import socket
from protocol import *
from common import decrypt_text, encrypt_text, ask_key
import ciphers as C

OUT_DIR = "server_data"
FILE_TO_CLIENT = os.path.join("sample_files", "file_10KB.txt")
os.makedirs(OUT_DIR, exist_ok=True)


def banner(t): print("\n" + "=" * 8, t, "=" * 8)


def handle_text(conn, h, payload):
    algo, key = h["algo"], h["key"]
    banner(f"MESSAGE FROM CLIENT  [{ALGOS[algo]}, key={key}]")
    plain, cipher = decrypt_text(algo, key, payload)
    print("Received ciphertext :", cipher)
    print("Decrypted plaintext :", plain)
    # ---- server replies
    reply = input("\nServer -> Client message (blank = no reply): ")
    if reply:
        wire, shown = encrypt_text(algo, key, reply)
        banner("MESSAGE TO CLIENT")
        print("Plaintext  :", reply)
        print("Ciphertext :", shown)
        send_frame(conn, {"type": "text", "algo": algo, "key": key}, wire)
    else:
        send_frame(conn, {"type": "ack"})


def handle_file(conn, h, payload):
    key = h["key"]
    banner(f"FILE FROM CLIENT  '{h['name']}'  [SDES, key={key}]")
    plain = C.sdes_decrypt_bytes(payload, key)
    print(f"Size                : {len(payload):,} bytes")
    print("Ciphertext (hex)    :", hex_preview(payload))
    print("Plaintext (preview) :", text_preview(plain))
    ok = sha256(plain) == h["sha256"]
    print("SHA-256 matches original:", ok)
    with open(os.path.join(OUT_DIR, "cipher_" + h["name"]), "wb") as f: f.write(payload)
    with open(os.path.join(OUT_DIR, "decrypted_" + h["name"]), "wb") as f: f.write(plain)
    print(f"Saved to {OUT_DIR}/ (cipher_*, decrypted_*)")
    send_frame(conn, {"type": "ack", "ok": ok})


def handle_file_request(conn, h):
    key = h["key"]
    with open(FILE_TO_CLIENT, "rb") as f: plain = f.read()
    cipher = C.sdes_encrypt_bytes(plain, key)
    banner(f"FILE TO CLIENT  '{os.path.basename(FILE_TO_CLIENT)}'  [SDES, key={key}]")
    print(f"Size                : {len(plain):,} bytes")
    print("Plaintext (preview) :", text_preview(plain))
    print("Ciphertext (hex)    :", hex_preview(cipher))
    send_frame(conn, {"type": "file", "name": os.path.basename(FILE_TO_CLIENT), "key": key,
                      "sha256": sha256(plain)}, cipher)


def main():
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT)); srv.listen(1)
    print(f"Server listening on {HOST}:{PORT} ...")
    while True:
        conn, addr = srv.accept()
        print("Client connected:", addr)
        try:
            while True:
                h, payload = recv_frame(conn)
                t = h["type"]
                if t == "text": handle_text(conn, h, payload)
                elif t == "file": handle_file(conn, h, payload)
                elif t == "get_file": handle_file_request(conn, h)
                elif t == "bye": break
        except (ConnectionError, OSError):
            pass
        conn.close(); print("Client disconnected.")


if __name__ == "__main__":
    main()
