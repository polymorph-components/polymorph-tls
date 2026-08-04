#!/usr/bin/env python3
"""Asserts no table-based AES implementation reached a wasm artifact.

Scans for the AES S-box, inverse S-box, and the first T-table (both byte
orders) as contiguous constants. A hit means the class-C failure mode: a
table-based AES with secret-indexed loads was linked instead of the
fixsliced implementation the profile requires.
"""

import sys

TABLES = {
    "AES S-box": "637c777bf26b6fc53001672bfed7ab76",
    "AES inverse S-box": "52096ad53036a538bf40a39e81f3d7fb",
    "AES T-table Te0 (LE)": "c66363a5f87c7c84ee777799f67b7b8d",
    "AES T-table Te0 (BE)": "a56363c6847c7cf8997777ee8d7b7bf6",
}


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <artifact.wasm>", file=sys.stderr)
        return 2
    path = sys.argv[1]
    with open(path, "rb") as f:
        data = f.read()
    found = [name for name, hexbytes in TABLES.items() if bytes.fromhex(hexbytes) in data]
    if found:
        print(f"{path}: table constants found: {', '.join(found)}", file=sys.stderr)
        return 1
    print(f"{path}: no AES table constants ({len(data)} bytes scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
