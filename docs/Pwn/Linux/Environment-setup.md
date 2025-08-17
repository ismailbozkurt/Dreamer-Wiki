
# Docker Environment Setup

## Introduction

Binary exploitation often requires a controlled environment—where specific versions of libraries, kernels, and tools can be isolated and manipulated without affecting your host system. Docker provides a lightweight, reproducible solution to this.

Whether you're practicing heap exploitation, ret2libc, or kernel-level fuzzing, using Docker ensures:

- A consistent exploit dev environment
- Easy sharing of challenges or setups    
- Quick resets after accidental corruption
- Safer handling of malicious binaries    

In this section, we’ll walk through setting up a Docker environment tailored for Linux binary exploitation.

There are several pre-existing environments available on the web for binary exploitation and reverse engineering. However, the shared Docker setup is designed to be **optimized and adaptable for various use cases and operating systems**.

While disassembler tools such as **IDA Pro**, **Binary Ninja**, **Ghidra**, and **EDB** can technically be integrated into the Docker container, this setup intentionally keeps such GUI-based tools on the **host system**. This approach ensures better performance, easier GUI handling, and more seamless interaction with large projects—while maintaining a clean and portable CLI-focused environment inside the container.

## Tools Installed in the Dockerfile

### Dockerfile

```dockerfile
# =========================================================
#  CTF Exploitation Dockerfile
#  Base: Ubuntu 24.04
#  Inspired by LiveOverflow's pwn_docker_example
# =========================================================
### 
# Build the docker container -> build.sh 
# Run the docker container -> run.sh 
# Get a shell in the container -> shell.sh

FROM ubuntu:24.04

ENV LC_CTYPE=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------
# Copy configs (rizin)
# ---------------------------------------------------------
COPY dot_rizinrc /root/.rizinrc

# ---------------------------------------------------------
# Core system packages
# ---------------------------------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        git \
        build-essential \
        file \
        elfutils \
        patchelf \
        gdbserver \
        jq \
        strace \
        ltrace \
        rubygems \
        gcc \
        dnsutils \
        netcat-traditional \
        ipython3 \
        gcc-multilib \
        net-tools \
        vim \
        gdb \
        gdb-multiarch \
        python3-full \
        python3-pip \
        python3-dev \
        libssl-dev \
        libffi-dev \
        make \
        procps \
        pipx \
        libpcre3-dev \
        libdb-dev \
        libxt-dev \
        libxaw7-dev \
        emacs-nox \
        pkg-config \
        liblzma-dev \
        socat \
        rr \
        clang \
        llvm \
        lldb \
        ruby-dev \
        tmux && \
    rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------
# Rust installation (via rustup)
# ---------------------------------------------------------
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain stable

# Cargo binaries -> add to PATH permanently
ENV PATH="/root/.cargo/bin:${PATH}"

# Quick check (not required but useful for build logs)
RUN rustup --version && cargo --version

# ---------------------------------------------------------
# Python tools
# ---------------------------------------------------------
RUN pipx ensurepath && \
    pipx install uv && \
    pip3 install --break-system-packages \
        capstone \
        requests \
        pwntools \
        r2pipe \
        keystone-engine \
        unicorn \
        ropper \
        meson \
        ninja \
        z3-solver \
        pyvex \
        archinfo \
        angr \
        frida-tools \
        angrop

# ---------------------------------------------------------
# Exploitation tools
# ---------------------------------------------------------
RUN mkdir /tools && cd /tools && \
    git clone https://github.com/JonathanSalwan/ROPgadget && \
    git clone https://github.com/niklasb/libc-database && \
    wget -O /root/.tmux.conf -q \
        https://raw.githubusercontent.com/ismailbozkurt/HACKTHEBOX-WRITEUPS/refs/heads/master/.tmux.conf-updated && \
    git clone --recurse-submodules https://github.com/rizinorg/rizin && \
    cd rizin && meson build && ninja -C build && ninja -C build install && \
    cd /tools && git clone https://github.com/radareorg/radare2 && \
    radare2/sys/install.sh

# ---------------------------------------------------------
# one_gadget (Ruby gem)
# ---------------------------------------------------------
RUN gem install one_gadget
RUN gem install seccomp-tools
# ---------------------------------------------------------
# Rust-based exploitation tools
# ---------------------------------------------------------
RUN cargo install ropr
RUN cargo install pwninit 

# ---------------------------------------------------------
# pwndbg & gef
# ---------------------------------------------------------
RUN cd /tools && \
    git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && ./setup.sh && \
    cd /tools && git clone https://github.com/bata24/gef && \
    cd gef && bash ./install.sh

# ---------------------------------------------------------
# Copy gdbinit configuration
# ---------------------------------------------------------
COPY dot_gdbinit /root/.gdbinit
```

#### Binary Exploitation & Reverse Engineering

|Tool|Description|
|---|---|
|`gdb` / `gdb-multiarch`|GNU Debugger, multiarch supports 32-bit/64-bit & ARM targets|
|`pwndbg`|A GDB enhancement for exploit dev with context display, heap inspection, etc.|
|`gef`|GDB Enhanced Features – an alternative to pwndbg, especially good for heap debugging|
|`gdbserver`|Remote debugging helper for GDB|
|`ROPgadget`|Finds ROP/JOP gadgets in binaries for building ROP chains|
|`ropper`|Another powerful ROP gadget finder with symbol and section parsing|
|`one_gadget`|Extracts useful libc one-gadget RCE offsets (e.g. `execve("/bin/sh")`)|
|`libc-database`|A tool to match remote libc versions using leaked addresses|
|`capstone`|Lightweight multi-architecture disassembly engine|
|`unicorn`|Lightweight multi-architecture CPU emulator|
|`keystone-engine`|Lightweight assembler supporting multiple architectures|
|`z3-solver`|The Z3 theorem solver from Microsoft – useful for symbolic execution|
|`pyvex`, `archinfo`|Used by angr or similar frameworks for binary analysis|
|`ltrace` / `strace`|Traces library calls and syscalls respectively|
|`file`, `elfutils`|Basic tools for ELF file inspection|
|`patchelf`|Modify ELF binaries – e.g. change interpreter, add/remove sections|
|`rizin`|Reverse engineering framework (a fork of radare2 with improvements)|
|`radare2`|Lightweight but powerful reverse engineering framework|
|`r2pipe`|Python bindings for interacting with rizin/radare2 from scripts|

---

#### Compilation & Development

|Tool|Description|
|---|---|
|`build-essential`, `gcc`, `make`|Standard compilation toolchain|
|`gcc-multilib`|Enables compiling 32-bit binaries on 64-bit systems|
|`python3-full`, `python3-dev`|Full Python3 environment with development headers|
|`pip`, `pipx`, `uv`|Python package managers – `pipx` installs Python apps in isolation|
|`cargo`, `rust`|Rust language support for tools like `ropr`|
|`ropr`|Rust-based ROP gadget search tool|

---

#### Networking & Utilities

|Tool|Description|
|---|---|
|`netcat-traditional`|Simple networking tool for reverse shells and socket testing|
|`dnsutils`|Tools like `dig` for DNS querying|
|`ipython3`|Interactive Python shell for testing logic and payloads|
|`jq`|Command-line JSON parser|
|`curl`, `wget`|Download files from the internet|
|`procps`|Tools like `ps`, `top` etc. for process inspection|
|`bsdmainutils`|Includes `hexdump`, `column`, and other useful tools|
|`vim`, `emacs-nox`, `tmux`|Editors and terminal multiplexer for working inside the container|
|`net-tools`|Legacy networking tools (`ifconfig`, `netstat`, etc.)|

### dot_gdbinit

This `.gdbinit` file configures GDB to automatically load **Pwndbg**, a powerful debugging plugin for binary exploitation. The commented line provides an alternative to load **GEF (GDB Enhanced Features)** manually, allowing easy switching between the two tools depending on preference.

```bash
source /tools/pwndbg/gdbinit.py
#python sys.path.insert(0, "/root/.gef"); from gef import *; Gef.main()
```


### dot_rizin

This `.rizinrc` file configures **Rizin** with user preferences for disassembly and UI. It enables inline comments (`asm.cmt.right`), pseudo-instructions (`asm.pseudo`), sets the color theme to `darkda`, forces UTF-8 output (`scr.utf8`), and allows slower but more accurate debugging (`dbg.slow`).

```bash
e asm.cmt.right=true
e asm.pseudo=true
eco darkda
e scr.utf8=true
e dbg.slow=true
```

### build.sh

This `build.sh` script is a simple wrapper that builds the Docker image using the specified `Dockerfile`. It tags the resulting image as `docker-binaryexploitation:ubuntu24.04`, making it easier to reference and run later.

```bash
docker build -f Dockerfile -t docker-binaryexploitation:ubuntu24.04 .
```

### run.sh

This `run.sh` script launches the Docker container in the background with privileges suited for debugging and exploitation tasks. It:

- Mounts the current directory to `/host` and a `logs/` folder to `/logs`
- Enables `SYS_PTRACE` and disables seccomp for full debugging capability
- Runs in detached mode (`-d`) with the name `docker-binaryexploitation`
- Uses the built image `docker-binaryexploitation:ubuntu24.04`
- Grants `--privileged` access to allow low-level operations such as ptrace, network manipulation, and device access

```bash
#!/bin/sh
docker run --rm \
  -v "$(pwd):/host" \
  -v "$(pwd)/logs:/logs" \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -d --name docker-binaryexploitation \
  -it docker-binaryexploitation:ubuntu24.04
```

### shell.sh

This `shell.sh` script opens an interactive bash shell inside the running `docker-binaryexploitation` container. It allows you to interact directly with the container’s environment as if you were logged into a Linux system.

```bash
#!/bin/sh
docker exec -it docker-binaryexploitation /bin/bash
```


## References

- [https://ctf-wiki.org/pwn/linux/user-mode/environment/](https://ctf-wiki.org/pwn/linux/user-mode/environment/)
- [https://github.com/LiveOverflow/pwn_docker_example](https://github.com/LiveOverflow/pwn_docker_example)

## TODO

- [ ] TODO: The Docker installation process will be replaced with `Ansible`