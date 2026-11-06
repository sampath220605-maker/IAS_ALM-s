"""ALM-1 client. Run after server:  python client.py"""
import os
import socket
from protocol import *
from common import encrypt_text, decrypt_text, ask_key
import ciphers as C

OUT_DIR = "client_data"
FILE_TO_SERVER = os.path.join("sample_files", "file_1MB.txt")
os.makedirs(OUT_DIR, exist_ok=True)


def banner(t): print("\n" + "=" * 8, t, "=" * 8)


def choose_algo():
    print("\nAvailable algorithms:")
    for k, v in ALGOS.items(): print(f"  {k}. {v}")
    while True:
        try:
            a = int(input("Choose algorithm (1-3): "))
            if a in ALGOS: return a, ask_key(a)
        except ValueError: pass
        print("  Please enter 1, 2 or 3.")


def send_message(sock, algo, key):
    msg = input("Enter plaintext message: ")
    wire, shown = encrypt_text(algo, key, msg)
    banner(f"SENDING  [{ALGOS[algo]}, key={key}]")
    if algo == 2: print("Playfair square:\n" + C.playfair_square_str(key))
    print("Plaintext  :", msg)
    print("Ciphertext :", shown)
    send_frame(sock, {"type": "text", "algo": algo, "key": key}, wire)
    print("\n(waiting for server reply...)")
    h, payload = recv_frame(sock)
    if h["type"] == "text":
        plain, cipher = decrypt_text(h["algo"], h["key"], payload)
        banner("REPLY FROM SERVER")
        print("Ciphertext :", cipher)
        print("Plaintext  :", plain)
    else:
        print("Server sent no reply.")


def send_file(sock):
    key = ask_key(3)
    with open(FILE_TO_SERVER, "rb") as f: plain = f.read()
    cipher = C.sdes_encrypt_bytes(plain, key)
    banner(f"SENDING FILE '{os.path.basename(FILE_TO_SERVER)}'  [SDES, key={key}]")
    print(f"Size                : {len(plain):,} bytes")
    print("Plaintext (preview) :", text_preview(plain))
    print("Ciphertext (hex)    :", hex_preview(cipher))
    send_frame(sock, {"type": "file", "name": os.path.basename(FILE_TO_SERVER), "key": key,
                      "sha256": sha256(plain)}, cipher)
    h, _ = recv_frame(sock)
    print("Server confirmed integrity:", h.get("ok"))


def receive_file(sock):
    key = ask_key(3)
    send_frame(sock, {"type": "get_file", "key": key})
    h, cipher = recv_frame(sock)
    plain = C.sdes_decrypt_bytes(cipher, h["key"])
    banner(f"FILE FROM SERVER '{h['name']}'  [SDES, key={h['key']}]")
    print(f"Size                : {len(cipher):,} bytes")
    print("Ciphertext (hex)    :", hex_preview(cipher))
    print("Plaintext (preview) :", text_preview(plain))
    print("SHA-256 matches original:", sha256(plain) == h["sha256"])
    with open(os.path.join(OUT_DIR, "cipher_" + h["name"]), "wb") as f: f.write(cipher)
    with open(os.path.join(OUT_DIR, "decrypted_" + h["name"]), "wb") as f: f.write(plain)
    print(f"Saved to {OUT_DIR}/ (cipher_*, decrypted_*)")


def main():
    sock = socket.create_connection((HOST, PORT))
    print(f"Connected to server {HOST}:{PORT}")
    algo, key = choose_algo()
    while True:
        print(f"\n--- Menu (current: {ALGOS[algo]}, key={key}) ---")
        print("1. Send text message to server (server replies)")
        print("2. Change algorithm / key")
        print("3. Send 1 MB file to server (SDES)")
        print("4. Receive 10 KB file from server (SDES)")
        print("5. Quit")
        c = input("Choice: ").strip()
        try:
            if c == "1": send_message(sock, algo, key)
            elif c == "2": algo, key = choose_algo()
            elif c == "3": send_file(sock)
            elif c == "4": receive_file(sock)
            elif c == "5":
                send_frame(sock, {"type": "bye"}); break
        except ConnectionError:
            print("Server disconnected."); break
    sock.close()


if __name__ == "__main__":
    main()
