# Docker Environment Setup

## Introduction

Didn't optimized yet. Explanation add later. Build take too long.

```dockerfile
# =========================================================
#  FUZZING (lightweight) — Debian 12 slim
#  AFL++ (LLVM/QEMU/Unicorn), Honggfuzz, pwntools, GEF
# =========================================================
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C.UTF-8 LANG=C.UTF-8

# ---------- Core build & toolchain ----------
RUN apt-get update && apt-get install -y --no-install-recommends \
    # toolchain
    build-essential clang lld lldb llvm \
    gcc-multilib g++-multilib \
    # build tools
    make cmake ninja-build pkg-config python3 python3-pip python3-setuptools pipx\
    git curl ca-certificates file xz-utils unzip \
    # debug
    gdb gdbserver strace ltrace rr \
    # libs for honggfuzz/qemu-mode
    libunwind-dev binutils-dev libbfd-dev libcapstone-dev zlib1g-dev liblzma-dev libglib2.0-dev libpixman-1-dev \
    # qemu-mode deps
    automake autoconf libtool libglib2.0-dev libpixman-1-dev \
    # helpers
    ruby ruby-dev procps net-tools wget curl vim tmux \
 && rm -rf /var/lib/apt/lists/*

# ---------- Python tooling ----------
RUN pipx ensurepath && \
    pipx install uv
RUN pip3 install --no-cache-dir --break-system-packages \
    pwntools \
    capstone unicorn keystone-engine \
    ropper \
    z3-solver

# ---------- Tmux ----------
RUN wget -O /root/.tmux.conf -q \
        https://raw.githubusercontent.com/ismailbozkurt/HACKTHEBOX-WRITEUPS/refs/heads/master/.tmux.conf-updated

# ---------- Ruby gems ----------
RUN gem install --no-document one_gadget seccomp-tools

# ---------- Tools workspace ----------
RUN mkdir -p /tools && cd /tools && \
    git clone --depth=1 https://github.com/JonathanSalwan/ROPgadget && \
    git clone --depth=1 https://github.com/niklasb/libc-database

# ---------- GEF (bata) ----------
RUN cd /tools && \
    git clone --depth=1 https://github.com/bata24/gef && \
    /tools/gef/install.sh || true
# (Optional pwndbg)
# RUN cd /tools && git clone --depth=1 https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh -y || true

# Default .gdbinit: only GEF (bata)
#RUN printf "source ~/.gdbinit-gef.py\n" >> /root/.gdbinit || true
RUN wget -q https://raw.githubusercontent.com/bata24/gef/dev/install-uv.sh -O- | sh
RUN python3 /root/.gef/gef.py --upgrade

# ---------- AFL++ (full features: llvm+qemu+unicorn) ----------
ENV AFL_SKIP_CPUFREQ=1
RUN git clone https://github.com/AFLplusplus/AFLplusplus /tools/AFLplusplus && \
    make -C /tools/AFLplusplus -j"$(nproc)" \
      LLVM_CONFIG=llvm-config \
      CC=clang CXX=clang++ \
      PYTHON3=python3 \
      SOURCE_ONLY=0 \
      AFL_NO_X86=0 && \
    make -C /tools/AFLplusplus install && \
    cd /tools/AFLplusplus/unicorn_mode && \
    /bin/bash ./build_unicorn_support.sh 
# ---------- Honggfuzz ----------
RUN git clone https://github.com/google/honggfuzz.git /tools/honggfuzz && \
    make -C /tools/honggfuzz -j"$(nproc)"
ENV PATH="/tools/honggfuzz:${PATH}"

# ---------- afl-unicorn (unicorn-mode) ----------
#RUN cd /tools && \
#	git clone https://github.com/shandianchengzi/unicorn_mode && \
#    	cd /tools/unicorn_mode && \
#	bash build_unicorn_support.sh
#
# ---------- Clean up ----------
WORKDIR /host
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
```

## TODO
- [ ] Add explanation
- [ ] Optimize installation steps
- [ ] Change installation process with `Ansible`