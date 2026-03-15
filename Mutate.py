#!/usr/bin/env python3
"""
Mutate.py - Post-build PE metadata randomizer

Randomizes PE headers and section padding to change the file hash
without affecting functionality. Called automatically by build.bat.
"""

import sys
import os
import struct
import random


def mutate_pe(path):
    with open(path, 'rb') as f:
        data = bytearray(f.read())

    if data[:2] != b'MZ':
        print("[!] Not a valid PE (no MZ)")
        return False

    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
        print("[!] Not a valid PE (no PE signature)")
        return False

    # 1. Randomize TimeDateStamp (PE header + 0x08)
    rand_ts = random.randint(0x5D000000, 0x67000000)
    struct.pack_into('<I', data, pe_offset + 8, rand_ts)

    # 2. Randomize Rich header (between DOS stub and PE signature)
    rich_pos = data.find(b'Rich', 0x40, pe_offset)
    if rich_pos > 0:
        dos_stub_end = 0x80
        rich_end = rich_pos + 8
        for i in range(dos_stub_end, min(rich_end, pe_offset)):
            data[i] = random.randint(0, 255)

    # 3. Zero the checksum (valid for EXEs, Windows ignores it)
    opt_header = pe_offset + 24
    checksum_offset = opt_header + 64
    struct.pack_into('<I', data, checksum_offset, 0)

    # 4. Randomize section alignment padding
    num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
    opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
    section_table = pe_offset + 24 + opt_header_size

    for i in range(num_sections):
        sec = section_table + i * 40
        virt_size = struct.unpack_from('<I', data, sec + 8)[0]
        raw_size = struct.unpack_from('<I', data, sec + 16)[0]
        raw_ptr = struct.unpack_from('<I', data, sec + 20)[0]

        if raw_size > virt_size and raw_ptr > 0:
            pad_start = raw_ptr + virt_size
            pad_end = raw_ptr + raw_size
            if pad_end <= len(data):
                for j in range(pad_start, pad_end):
                    data[j] = random.randint(0, 255)

    with open(path, 'wb') as f:
        f.write(data)

    return True


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <executable>")
        sys.exit(1)

    exe = sys.argv[1]
    if not os.path.isfile(exe):
        print(f"[!] File not found: {exe}")
        sys.exit(1)

    if mutate_pe(exe):
        import hashlib
        with open(exe, 'rb') as f:
            h = hashlib.sha256(f.read()).hexdigest()
        print(f"[+] PE mutated: {exe}")
        print(f"[+] SHA-256: {h[:16]}...")
    else:
        print("[!] Mutation failed")
        sys.exit(1)
