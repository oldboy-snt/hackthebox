from pwn import *
from termcolor import colored

text = colored(' DEBUG ', 'red', attrs=['reverse', 'blink', 'bold'])
context.log_level = 'DEBUG'
DEBUG = 1
file = './fancy_names'
exe  = ELF(file)

def main(io, libc=None):
    # declared
    # exploit
    pass

if __name__ == '__main__':
    if DEBUG:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        #env = {'LD_PRELOAD': os.path.join(os.getcwd(), 'libc.so.6')}
        #io = process([os.path.join(os.getcwd(), 'ld-linux.so.2'), file], env=env)
        io = process(file)
        input(text)
    else:
        libc = ELF('./libc.so.6')
        io = remote('chall.pwnable.tw', 1337)
    
    main(io, libc)
    io.interactive()