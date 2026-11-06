"""Shared helpers used by both client and server."""
import ciphers as C


def encrypt_text(algo, key, text):
    """Return (ciphertext_bytes_for_wire, printable_ciphertext)."""
    if algo == 1:
        ct = C.caesar_encrypt(text, int(key)); return ct.encode(), ct
    if algo == 2:
        ct = C.playfair_encrypt(text, key); return ct.encode(), ct
    raw = C.sdes_encrypt_bytes(text.encode(), key)
    return raw, raw.hex(' ')


def decrypt_text(algo, key, payload):
    if algo == 1:
        return C.caesar_decrypt(payload.decode(), int(key)), payload.decode()
    if algo == 2:
        return C.playfair_decrypt(payload.decode(), key), payload.decode()
    return C.sdes_decrypt_bytes(payload, key).decode(errors="replace"), payload.hex(' ')


def ask_key(algo):
    while True:
        try:
            if algo == 1:
                return str(int(input("Enter Caesar shift (integer): ")))
            if algo == 2:
                k = input("Enter Playfair keyword (letters): ").strip()
                if not any(c.isalpha() for c in k): raise ValueError("keyword needs letters")
                return k
            return C.sdes_validate_key(input("Enter 10-bit SDES key (e.g. 1010000010): "))
        except ValueError as e:
            print("  Invalid key:", e)
