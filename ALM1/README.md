# ALM-1: Client-Server Cryptography Program (Python 3, no external libraries)

## Files
| File | Purpose |
|---|---|
| `ciphers.py` | Caesar, Playfair, S-DES implementations (S-DES works on text and raw bytes) |
| `protocol.py` / `common.py` | Socket framing and shared helpers |
| `server.py` | Server: shows ciphertext + decrypted text, then replies to the client |
| `client.py` | Client: algorithm menu, send/receive messages and files |
| `gen_files.py` | Regenerates `sample_files/file_1MB.txt` and `file_10KB.txt` |
| `test_ciphers.py` | Unit tests (known S-DES and Playfair test vectors) |

## How to run (three terminals / steps)
1. `python test_ciphers.py`   (optional self-test)
2. Terminal 1: `python server.py`
3. Terminal 2: `python client.py`

## ALM requirements covered
1. Client-server program in Python (TCP sockets, `127.0.0.1:5000`).
2. Client lists algorithms: **1. Caesar Cipher, 2. Playfair Cipher, 3. SDES** and asks for a key.
3. Menu option 1: client sends a message and **displays the ciphertext** (and plaintext).
4. Server receives it and **displays ciphertext and decrypted plaintext**.
5. Server then types a reply; **both server and client display ciphertext and plaintext** of it.

## ALM-1 tutorial problems
1. Two algorithms chosen: **Caesar Cipher** and **Playfair Cipher** (S-DES is the third).
2. **S-DES file transfer**
   - i. Menu option 3: sends `sample_files/file_1MB.txt` (1 MB) client -> server. Both sides print the
     ciphertext (hex) and plaintext preview; the server saves `cipher_*` and `decrypted_*` in `server_data/`
     and verifies the SHA-256 against the original.
   - ii. Menu option 4: the server sends `sample_files/file_10KB.txt` (10 KB) -> client, which shows the
     ciphertext and plaintext and saves them in `client_data/`.

## Demo inputs
- Caesar: shift `3`; message `Hello World` -> `Khoor Zruog`
- Playfair: keyword `monarchy`; message `attack at dawn` -> `RSSRDERSBRNY`
  (decrypts to `ATTACKATDAWN`: upper case, no spaces, J=I, filler `X` where needed)
- S-DES: key `1010000010` (10 bits)

## Notes
- The algorithm and key are sent in each message header for simplicity (a real system would use
  a pre-shared key or key exchange). The server reuses the same algorithm/key for its reply.
- S-DES works on 8-bit blocks (ECB, one byte per block), so large files are encrypted via a
  256-entry lookup table; 1 MB takes well under a second. Note that ECB mode leaks patterns,
  which is fine for a tutorial but not for real security.
- Change `HOST`/`PORT` in `protocol.py` to run on two machines.
