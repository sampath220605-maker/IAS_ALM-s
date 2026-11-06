"""ALM2 client: sends a ~10 KB encrypted text file, then receives the server's ~5 KB file."""
import argparse, json, os, socket
from aes_utils import aes_encrypt, aes_decrypt, show, DEFAULT_PASSPHRASE
from net_utils import send_msg, recv_msg

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5001)
    ap.add_argument("--passphrase", default=DEFAULT_PASSPHRASE)
    ap.add_argument("--file", default=os.path.join(HERE, "data", "client_10kb.txt"))
    ap.add_argument("--brief", action="store_true", help="truncate the on-screen display")
    args = ap.parse_args()
    os.makedirs(os.path.join(HERE, "received"), exist_ok=True)

    with open(args.file, "rb") as f: data = f.read()
    with socket.create_connection((args.host, args.port)) as s:
        print(f"[CLIENT] Connected to {args.host}:{args.port}")

        # ---- Step 1: send client file (Client -> Server) ----
        salt, iv, cipher = aes_encrypt(data, args.passphrase)
        show(f"[CLIENT] SENDING '{os.path.basename(args.file)}' to server", data, cipher, args.brief)
        send_msg(s, json.dumps({"filename": os.path.basename(args.file),
                                "salt": salt.hex(), "iv": iv.hex()}).encode())
        send_msg(s, cipher)
        print("[CLIENT] File sent. Waiting for server file ...")

        # ---- Step 2: receive server file (Server -> Client) ----
        hdr = json.loads(recv_msg(s).decode())
        cipher = recv_msg(s)
        plain = aes_decrypt(cipher, args.passphrase, bytes.fromhex(hdr["salt"]), bytes.fromhex(hdr["iv"]))
        show(f"[CLIENT] RECEIVED '{hdr['filename']}' from server", plain, cipher, args.brief,
             order=("cipher", "plain"))
        out = os.path.join(HERE, "received", "from_server_" + hdr["filename"])
        with open(out, "wb") as f: f.write(plain)
        with open(out + ".enc", "wb") as f: f.write(cipher)
        print(f"[CLIENT] Saved decrypted file -> {out}  (+ .enc ciphertext)")


if __name__ == "__main__":
    main()
