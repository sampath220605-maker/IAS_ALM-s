"""Generate the 1 MB and 10 KB sample files (readable text so plaintext is displayable)."""
import os
os.makedirs("sample_files", exist_ok=True)
base = ("Active Learning Management - ALM 1. Network security tutorial: classical and "
        "block ciphers protect confidentiality of data in transit. {:07d}\n")

def make(path, size):
    out, i = bytearray(), 0
    while len(out) < size:
        out += base.format(i).encode(); i += 1
    open(path, "wb").write(bytes(out[:size]))
    print(path, size, "bytes")

make("sample_files/file_1MB.txt", 1024 * 1024)
make("sample_files/file_10KB.txt", 10 * 1024)
