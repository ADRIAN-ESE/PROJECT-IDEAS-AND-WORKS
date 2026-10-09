"""Minimal, dependency-free QR Code generator (byte mode, ECC level M, versions 1-10).

Enough for otpauth:// provisioning URIs (up to ~210 bytes). Output is an SVG data URI.
"""
import base64

# version -> (ec codewords per block, [(block_count, data_codewords_per_block), ...])
_EC_M = {
    1: (10, [(1, 16)]), 2: (16, [(1, 28)]), 3: (26, [(1, 44)]), 4: (18, [(2, 32)]),
    5: (24, [(2, 43)]), 6: (16, [(4, 27)]), 7: (18, [(4, 31)]),
    8: (22, [(2, 38), (2, 39)]), 9: (22, [(3, 36), (2, 37)]), 10: (26, [(4, 43), (1, 44)]),
}
_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
          7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}


def _gf_mul(x, y):
    z = 0
    for i in range(7, -1, -1):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree):
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 2)
    return result


def _rs_remainder(data, divisor):
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, c in enumerate(divisor):
            result[i] ^= _gf_mul(c, factor)
    return result


def _bit(x, i):
    return (x >> i) & 1


def _build_codewords(data: bytes):
    for ver in range(1, 11):
        ec_len, groups = _EC_M[ver]
        capacity = sum(n * d for n, d in groups)
        count_bits = 8 if ver < 10 else 16
        need = 4 + count_bits + 8 * len(data)
        if need <= capacity * 8:
            break
    else:
        raise ValueError("data too long for built-in QR encoder")
    bits = [0, 1, 0, 0]
    bits += [_bit(len(data), i) for i in range(count_bits - 1, -1, -1)]
    for byte in data:
        bits += [_bit(byte, i) for i in range(7, -1, -1)]
    bits += [0] * min(4, capacity * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    cw = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(cw) < capacity:
        cw.append(pad)
        pad ^= 0xEC ^ 0x11
    blocks, pos = [], 0
    for n, d in groups:
        for _ in range(n):
            blocks.append(cw[pos:pos + d])
            pos += d
    divisor = _rs_divisor(ec_len)
    ecs = [_rs_remainder(b, divisor) for b in blocks]
    out = []
    for i in range(max(len(b) for b in blocks)):
        for b in blocks:
            if i < len(b):
                out.append(b[i])
    for i in range(ec_len):
        for e in ecs:
            out.append(e[i])
    return ver, out


class _Matrix:
    def __init__(self, ver):
        self.ver = ver
        self.size = ver * 4 + 17
        self.m = [[False] * self.size for _ in range(self.size)]
        self.f = [[False] * self.size for _ in range(self.size)]
        self._function_patterns()

    def _set(self, x, y, dark):
        self.m[y][x] = bool(dark)
        self.f[y][x] = True

    def _function_patterns(self):
        n = self.size
        for i in range(n):
            self._set(6, i, i % 2 == 0)
            self._set(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (n - 4, 3), (3, n - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < n and 0 <= y < n:
                        self._set(x, y, max(abs(dx), abs(dy)) not in (2, 4))
        pos = _ALIGN[self.ver]
        for i, py in enumerate(pos):
            for j, px in enumerate(pos):
                if (i == 0 and j == 0) or (i == 0 and j == len(pos) - 1) or (i == len(pos) - 1 and j == 0):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self._set(px + dx, py + dy, max(abs(dx), abs(dy)) != 1)
        self.format_bits(0)
        if self.ver >= 7:
            rem = self.ver
            for _ in range(12):
                rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
            bits = self.ver << 12 | rem
            for i in range(18):
                a, b = n - 11 + i % 3, i // 3
                self._set(a, b, _bit(bits, i))
                self._set(b, a, _bit(bits, i))

    def format_bits(self, mask):
        n = self.size
        data = 0 << 3 | mask  # ECC level M = 0b00
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412
        for i in range(0, 6):
            self._set(8, i, _bit(bits, i))
        self._set(8, 7, _bit(bits, 6))
        self._set(8, 8, _bit(bits, 7))
        self._set(7, 8, _bit(bits, 8))
        for i in range(9, 15):
            self._set(14 - i, 8, _bit(bits, i))
        for i in range(0, 8):
            self._set(n - 1 - i, 8, _bit(bits, i))
        for i in range(8, 15):
            self._set(8, n - 15 + i, _bit(bits, i))
        self._set(8, n - 8, True)

    def place(self, data):
        n, i = self.size, 0
        right = n - 1
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(n):
                for j in range(2):
                    x = right - j
                    upward = ((right + 1) & 2) == 0
                    y = (n - 1 - vert) if upward else vert
                    if not self.f[y][x] and i < len(data) * 8:
                        self.m[y][x] = bool(_bit(data[i >> 3], 7 - (i & 7)))
                        i += 1
            right -= 2

    def mask(self, k):
        for y in range(self.size):
            for x in range(self.size):
                if self.f[y][x]:
                    continue
                inv = [(x + y) % 2 == 0, y % 2 == 0, x % 3 == 0, (x + y) % 3 == 0,
                       (x // 3 + y // 2) % 2 == 0, x * y % 2 + x * y % 3 == 0,
                       (x * y % 2 + x * y % 3) % 2 == 0, ((x + y) % 2 + x * y % 3) % 2 == 0][k]
                if inv:
                    self.m[y][x] = not self.m[y][x]

    def penalty(self):
        n, m, score = self.size, self.m, 0
        lines = [row for row in m] + [[m[y][x] for y in range(n)] for x in range(n)]
        pat1, pat2 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0], [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1]
        for line in lines:
            run = 1
            for i in range(1, n):
                if line[i] == line[i - 1]:
                    run += 1
                else:
                    score += 3 + run - 5 if run >= 5 else 0
                    run = 1
            score += 3 + run - 5 if run >= 5 else 0
            li = [int(v) for v in line]
            for i in range(n - 10):
                seg = li[i:i + 11]
                if seg == pat1 or seg == pat2:
                    score += 40
        for y in range(n - 1):
            for x in range(n - 1):
                if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                    score += 3
        dark = sum(v for row in m for v in row)
        total = n * n
        score += ((abs(dark * 20 - total * 10) + total - 1) // total - 1) * 10
        return score


def make_matrix(data: bytes):
    ver, cw = _build_codewords(data)
    best, best_pen = None, None
    for k in range(8):
        mx = _Matrix(ver)
        mx.place(cw)
        mx.mask(k)
        mx.format_bits(k)
        p = mx.penalty()
        if best is None or p < best_pen:
            best, best_pen = mx, p
    return best.m


def svg_data_uri(text: str, scale: int = 6, border: int = 4) -> str:
    m = make_matrix(text.encode("utf-8"))
    n = len(m)
    size = (n + 2 * border) * scale
    path = "".join(f"M{x + border},{y + border}h1v1h-1z" for y, row in enumerate(m) for x, v in enumerate(row) if v)
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n + 2 * border} {n + 2 * border}" '
           f'width="{size}" height="{size}" shape-rendering="crispEdges">'
           f'<rect width="100%" height="100%" fill="#fff"/><path d="{path}" fill="#000"/></svg>')
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode()
