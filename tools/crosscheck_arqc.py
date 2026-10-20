#!/usr/bin/env python3
"""Independent re-implementation of the host's EMV key derivation and MACs,
written straight from EMV 4.3 Book 2 Annex A1 and ISO 9797-1, using the
`cryptography` package's TripleDES. Reads `eah-admin vectors N` JSON lines on
stdin and fails on the first value that differs.

    eah-admin vectors 2000 | python3 tools/crosscheck_arqc.py
"""
import json
import sys
import warnings

warnings.filterwarnings("ignore")  # TripleDES is "decrepit" in newer releases
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402


def tdes_ecb(key16: bytes, block: bytes, encrypt: bool = True) -> bytes:
    c = Cipher(algorithms.TripleDES(key16), modes.ECB())
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(block) + op.finalize()


def des(key8: bytes, block: bytes, encrypt: bool = True) -> bytes:
    return tdes_ecb(key8 + key8, block, encrypt)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def master_key_option_a(imk: bytes, pan: str, psn: str) -> bytes:
    digits = (pan + psn).rjust(16, "0")[-16:]
    y = bytes.fromhex(digits)
    return tdes_ecb(imk, y) + tdes_ecb(imk, xor(y, b"\xff" * 8))


def session_key_csk(mk: bytes, atc: int) -> bytes:
    a = atc.to_bytes(2, "big")
    return tdes_ecb(mk, a + b"\xf0" + bytes(5)) + tdes_ecb(mk, a + b"\x0f" + bytes(5))


def mac_alg3(key: bytes, data: bytes) -> bytes:
    data = data + b"\x80"
    data += bytes(-len(data) % 8)
    kl, kr = key[:8], key[8:]
    h = bytes(8)
    for i in range(0, len(data), 8):
        h = des(kl, xor(h, data[i:i + 8]))
    return des(kl, des(kr, h, encrypt=False))


def arpc_method1(sk: bytes, arqc: bytes, arc: bytes) -> bytes:
    return tdes_ecb(sk, xor(arqc, arc + bytes(6)))


def main() -> int:
    n = 0
    for line in sys.stdin:
        v = json.loads(line)
        imk = bytes.fromhex(v["imk"])
        mk = master_key_option_a(imk, v["pan"], v["psn"])
        sk = session_key_csk(mk, v["atc"])
        arqc = mac_alg3(sk, bytes.fromhex(v["data"]))
        arpc = arpc_method1(sk, arqc, bytes.fromhex(v["arc"]))
        for name, got in (("mk", mk), ("sk", sk), ("arqc", arqc), ("arpc", arpc)):
            if got.hex().upper() != v[name]:
                print(f"MISMATCH vector {n} {name}: python {got.hex().upper()} host {v[name]}")
                return 1
        n += 1
    print(f"crosscheck: {n} vectors, mk/sk/arqc/arpc all match")
    return 0 if n else 1


if __name__ == "__main__":
    sys.exit(main())
