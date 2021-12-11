#!/usr/bin/env python3
import sys
import os
import json
from typing import BinaryIO

from utils import is_PE, matches_bytes, find_block_pos, extract_json, extract_files, src_dir, is_simple
from injectionStrats import get_strategy

PE_SIGN = b"\x4d\x5a"

FUNCTION = b"!(function"
# Technically its 381 nulls in the sample I got
NULLS = 50
BLOCK_BEGIN = bytes(b"\x00" * NULLS + FUNCTION)
ZERO_SEPARATOR = b';;'

PAYLOAD = ";console.log({});process.exit(0);"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please provide a file to extract", file=sys.stderr)
        sys.exit(-1)

    if is_simple(sys.argv[1]):
        sys.exit(0)

    files = None
    kind = -1
    with open(sys.argv[1], "rb+") as f:
        if not is_PE(f):
            print("Was not a PE", file=sys.stderr)
            sys.exit(-1)

        block_pos = find_block_pos(f, BLOCK_BEGIN) + NULLS
        if block_pos is None:
            print("Error finding the NodeJS beginning", file=sys.stderr)
            sys.exit(-1)

        print(f"NodeJS starting: {hex(block_pos)}")

        zero_off = find_block_pos(
            f, ZERO_SEPARATOR, block_pos) + len(ZERO_SEPARATOR)
        if zero_off is None:
            print("Error finding the Malware 0 offset", file=sys.stderr)
            sys.exit(-1)

        print(f"Malware 0 offset: {hex(zero_off)}")

        files = extract_json(f, block_pos)
        if files is None:
            print("Error finding the json", file=sys.stderr)
            sys.exit(-1)

        kind = extract_files(f, files, zero_off, "./out/")
        if kind < 0:
            print("Error determining the kind", file=sys.stderr)
            sys.exit(-1)

    # End of code extraction
    print("------ Injection ------")
    # Now let's extract the webhook
    if files is None:
        print("Error finding the json", file=sys.stderr)
        sys.exit(-1)

    strategy = get_strategy(files, "./out/", kind,
                            PAYLOAD)

    if strategy is None:
        print("Failed to determine a strategy", file=sys.stderr)
        sys.exit(-1)

    strategy()
