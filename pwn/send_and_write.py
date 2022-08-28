from pwn import *
import re
import codecs
import base64


host, port = '20.126.227.19:45377'.split(':')
port = int(port)


# debug and log out
context.log_level = 'INFO'
log.info("starting exploit...")


# Command line arguments handling
target = remote(host, port)


# question one (solve the math)
target.recvlineS(13)
question = target.recvuntil(b"?:").decode("utf-8")
rpattern = re.compile(r'(\d\+\d)')
mo = rpattern.search(question)
solution = eval(mo.group())
info('question: ' + question)
success('sending solution: ' + str(solution) + '\n\n')
target.sendline(str.encode(str(solution)))


# question two (remove dashes)
target.recvlines(3)
question = target.recvuntil(b":").decode("utf-8")
rpattern = re.compile(r'([a-z]\-.*)', re.IGNORECASE)
mo = rpattern.search(question)
solution = mo.group().replace('-','')
solution = solution.replace(':','')
info('question: ' + question)
success('sending solution: ' + str(solution) + '\n\n')
target.sendline(str.encode(solution))


# question three (rot 13 decode)
target.recvlines(3)
question = target.recvuntil(b": \n").decode("utf-8")
info('question: ' + question)
question = question.replace(':','')
question = question.split(' ')[7]
solution = codecs.encode(question, 'rot_13')
success('sending solution: ' + str(solution) + '\n\n')
target.sendline(str.encode(solution))


# question four (base64 decode)
target.recvlines(2)
question = target.recvuntil(b": \n").decode("utf-8")
info('question: ' + question)
question = question.replace(':','')
question = question.split(' ')[5]
solution = base64.b64decode(question)
success('sending solution: ' + str(solution) + '\n\n')
target.sendline(solution)


# question five (hex decode)
target.recvlines(2)
question = target.recvuntil(b": \n").decode("utf-8")
info('question: ' + question)
question = question.replace(':','')
question = question.split(' ')[5]
solution = bytes.fromhex(question[2:]).decode('utf-8')
success('sending solution: ' + str(solution) + '\n\n')
target.sendline(str.encode(solution))


# question six (bit decode)
target.recvlines(2)
question = target.recvuntil(b": \n").decode("utf-8")
info('question: ' + question)
question = question.replace(':','')
question = question.split(' ')[4]
solution = int(question, 2)
success('sending solution: ' + str(solution) + '\n\n')
target.sendline(str.encode(str(solution)))


def sxor(s1,s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))


# question seven (xor string)
target.recvlines(3)
question = target.recvuntil(b":").decode("utf-8")
info('question: ' + question)
question = question.replace(':','')
question = question.split(' ')
s1 = question[1]
s2 = question[3]
solution = sxor(s1,s2)
success('sending solution: ' + str(solution) + '\n\n')
target.sendline(str.encode(solution))

# last question
target.recvlines(3)
question = target.recvuntil(b"?").decode("utf-8")
info('question: ' + question)
solution = "Judith Gerlach"
success('sending solution: ' + str(solution) + '\n\n')
target.sendline(str.encode(solution))
print(target.recvall().decode("utf-8"))








