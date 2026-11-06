"""Cipher implementations: Caesar, Playfair, Simple DES (S-DES)."""

# ---------------------------------------------------------------- Caesar
def caesar_encrypt(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if ch.isalpha() and ch.isascii():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return ''.join(out)


def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)


# --------------------------------------------------------------- Playfair
def _playfair_square(keyword: str):
    seen, square = set(), []
    for ch in (keyword.upper().replace('J', 'I') + "ABCDEFGHIKLMNOPQRSTUVWXYZ"):
        if ch.isalpha() and ch.isascii() and ch not in seen:
            seen.add(ch)
            square.append(ch)
    pos = {ch: divmod(i, 5) for i, ch in enumerate(square)}
    return square, pos


def _playfair_prepare(text: str):
    letters = [c for c in text.upper().replace('J', 'I') if c.isalpha() and c.isascii()]
    pairs, i = [], 0
    while i < len(letters):
        a = letters[i]
        b = letters[i + 1] if i + 1 < len(letters) else 'X'
        if a == b:
            pairs.append((a, 'X'))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    return pairs


def _playfair_crypt(pairs, keyword, direction):
    square, pos = _playfair_square(keyword)
    out = []
    for a, b in pairs:
        (r1, c1), (r2, c2) = pos[a], pos[b]
        if r1 == r2:
            c1, c2 = (c1 + direction) % 5, (c2 + direction) % 5
        elif c1 == c2:
            r1, r2 = (r1 + direction) % 5, (r2 + direction) % 5
        else:
            c1, c2 = c2, c1
        out.append(square[r1 * 5 + c1] + square[r2 * 5 + c2])
    return ''.join(out)


def playfair_encrypt(text: str, keyword: str) -> str:
    return _playfair_crypt(_playfair_prepare(text), keyword, 1)


def playfair_decrypt(text: str, keyword: str) -> str:
    """Returns upper-case text; J is shown as I and filler 'X' letters remain."""
    t = [c for c in text.upper() if c.isalpha()]
    pairs = [(t[i], t[i + 1]) for i in range(0, len(t) - 1, 2)]
    return _playfair_crypt(pairs, keyword, -1)


def playfair_square_str(keyword: str) -> str:
    sq, _ = _playfair_square(keyword)
    return '\n'.join(' '.join(sq[r * 5:r * 5 + 5]) for r in range(5))


# ------------------------------------------------------------------ S-DES
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]
S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]


def _perm(bits, table):
    return ''.join(bits[i - 1] for i in table)


def _xor(a, b):
    return ''.join('1' if x != y else '0' for x, y in zip(a, b))


def _shift(bits, n):
    return bits[n:] + bits[:n]


def _sbox(bits, box):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    return format(box[row][col], '02b')


def _fk(bits, key):
    left, right = bits[:4], bits[4:]
    x = _xor(_perm(right, EP), key)
    p4 = _perm(_sbox(x[:4], S0) + _sbox(x[4:], S1), P4)
    return _xor(left, p4) + right


def sdes_validate_key(key: str) -> str:
    key = key.strip()
    if len(key) != 10 or set(key) - {'0', '1'}:
        raise ValueError("S-DES key must be exactly 10 binary digits, e.g. 1010000010")
    return key


def sdes_subkeys(key: str):
    p10 = _perm(key, P10)
    l, r = _shift(p10[:5], 1), _shift(p10[5:], 1)
    k1 = _perm(l + r, P8)
    l, r = _shift(l, 2), _shift(r, 2)
    k2 = _perm(l + r, P8)
    return k1, k2


def sdes_encrypt_block(bits8: str, key: str) -> str:
    k1, k2 = sdes_subkeys(key)
    t = _perm(bits8, IP)
    t = _fk(t, k1)
    t = t[4:] + t[:4]
    t = _fk(t, k2)
    return _perm(t, IP_INV)


def sdes_decrypt_block(bits8: str, key: str) -> str:
    k1, k2 = sdes_subkeys(key)
    t = _perm(bits8, IP)
    t = _fk(t, k2)
    t = t[4:] + t[:4]
    t = _fk(t, k1)
    return _perm(t, IP_INV)


_table_cache = {}


def _tables(key: str):
    """256-entry lookup tables so large files are processed quickly (ECB, 1 byte = 1 block)."""
    if key not in _table_cache:
        enc = bytes(int(sdes_encrypt_block(format(b, '08b'), key), 2) for b in range(256))
        dec = bytes(int(sdes_decrypt_block(format(b, '08b'), key), 2) for b in range(256))
        _table_cache[key] = (enc, dec)
    return _table_cache[key]


def sdes_encrypt_bytes(data: bytes, key: str) -> bytes:
    return data.translate(_tables(sdes_validate_key(key))[0])


def sdes_decrypt_bytes(data: bytes, key: str) -> bytes:
    return data.translate(_tables(sdes_validate_key(key))[1])
