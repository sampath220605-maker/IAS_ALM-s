"""ALM2 server: receives the client's ~10 KB encrypted file, then sends its own ~5 KB file."""
import argparse, json, os, socket
from aes_utils import aes_encrypt, aes_decrypt, show, DEFAULT_PASSPHRASE
from net_utils import send_msg, recv_msg

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5001)
    ap.add_argument("--passphrase", default=DEFAULT_PASSPHRASE)
    ap.add_argument("--file", default=os.path.join(HERE, "data", "server_5kb.txt"))
    ap.add_argument("--brief", action="store_true", help="truncate the on-screen display")
    args = ap.parse_args()
    os.makedirs(os.path.join(HERE, "received"), exist_ok=True)

    with socket.socket() as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, args.port)); srv.listen(1)
        print(f"[SERVER] Listening on {args.host}:{args.port} ...")
        conn, addr = srv.accept()
        print(f"[SERVER] Client connected: {addr}")
        with conn:
            # ---- Step 1: receive client file (Client -> Server) ----
            hdr = json.loads(recv_msg(conn).decode())
            cipher = recv_msg(conn)
            plain = aes_decrypt(cipher, args.passphrase, bytes.fromhex(hdr["salt"]), bytes.fromhex(hdr["iv"]))
            show(f"[SERVER] RECEIVED '{hdr['filename']}' from client", plain, cipher, args.brief,
                 order=("cipher", "plain"))
            out = os.path.join(HERE, "received", "from_client_" + hdr["filename"])
            with open(out, "wb") as f: f.write(plain)
            with open(out + ".enc", "wb") as f: f.write(cipher)
            print(f"[SERVER] Saved decrypted file -> {out}  (+ .enc ciphertext)")

            # ---- Step 2: send server file (Server -> Client) ----
            with open(args.file, "rb") as f: data = f.read()
            salt, iv, cipher = aes_encrypt(data, args.passphrase)
            show(f"[SERVER] SENDING '{os.path.basename(args.file)}' to client", data, cipher, args.brief)
            send_msg(conn, json.dumps({"filename": os.path.basename(args.file),
                                       "salt": salt.hex(), "iv": iv.hex()}).encode())
            send_msg(conn, cipher)
            print("[SERVER] File sent. Done.")


if __name__ == "__main__":
    main()
