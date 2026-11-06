"""AES-256-CBC helpers built on PyCryptodome (PBKDF2 key derivation, PKCS#7 padding)."""
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

DEFAULT_PASSPHRASE = "ALM2-shared-secret"


def derive_key(passphrase: str, salt: bytes) -> bytes:
    return PBKDF2(passphrase, salt, dkLen=32, count=100_000, hmac_hash_module=SHA256)


def aes_encrypt(plain: bytes, passphrase: str):
    salt, iv = get_random_bytes(16), get_random_bytes(16)
    cipher = AES.new(derive_key(passphrase, salt), AES.MODE_CBC, iv)
    return salt, iv, cipher.encrypt(pad(plain, AES.block_size))


def aes_decrypt(cipher_bytes: bytes, passphrase: str, salt: bytes, iv: bytes) -> bytes:
    cipher = AES.new(derive_key(passphrase, salt), AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(cipher_bytes), AES.block_size)


def show(title: str, plain: bytes, cipher: bytes, brief: bool = False, order=("plain", "cipher")):
    """Pretty-print plaintext and ciphertext (hex, wrapped at 64 chars/line)."""
    text = plain.decode("utf-8", errors="replace")
    hexed = cipher.hex()
    wrapped = "\n".join(hexed[i:i + 64] for i in range(0, len(hexed), 64))
    if brief:
        text = text[:500] + ("\n... [truncated]" if len(text) > 500 else "")
        wrapped = wrapped[:800] + ("\n... [truncated]" if len(wrapped) > 800 else "")
    blocks = {
        "plain": f"--- PLAIN TEXT ({len(plain)} bytes) ---\n{text}",
        "cipher": f"--- CIPHER TEXT, AES-256-CBC hex ({len(cipher)} bytes) ---\n{wrapped}",
    }
    print("\n" + "=" * 70 + f"\n{title}\n" + "=" * 70)
    for k in order:
        print(blocks[k] + "\n")
