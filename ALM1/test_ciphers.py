import ciphers as C, os
# S-DES known vector (key 1010000010, plain 01110010 -> 01110111)
assert C.sdes_encrypt_block("01110010", "1010000010") == "01110111", C.sdes_encrypt_block("01110010", "1010000010")
assert C.sdes_subkeys("1010000010") == ("10100100", "01000011")
for b in range(256):
    s = format(b, "08b"); assert C.sdes_decrypt_block(C.sdes_encrypt_block(s, "1100110011"), "1100110011") == s
d = os.urandom(5000); assert C.sdes_decrypt_bytes(C.sdes_encrypt_bytes(d, "1010000010"), "1010000010") == d
assert C.caesar_decrypt(C.caesar_encrypt("Hello, World!", 3), 3) == "Hello, World!"
assert C.caesar_encrypt("abc xyz", 3) == "def abc"
assert C.playfair_encrypt("Hide the gold in the tree stump", "playfair example") == "BMODZBXDNABEKUDMUIXMMOUVIF"
assert C.playfair_decrypt("BMODZBXDNABEKUDMUIXMMOUVIF", "playfair example").startswith("HIDETHEGOLDINTHETREXESTUMP")
print("All cipher tests passed.")
