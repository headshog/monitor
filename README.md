# Инструкция по установке окружения

## Образ

1. Ставим с https://releases.ubuntu.com/22.04 "Desktop image for 64-bit PC (AMD64) computers (standard download)".

2. Маунтим shared директорию с монитором, либо копируем в хомку, кому как удобно.

2. В консоли после установки:

```bash
sudo apt update
sudo apt upgrade
sudo apt install -y clang libbpf-dev make linux-tools-common linux-tools-generic pkgconf build-essential clang llvm libelf-dev zlib1g-dev git make pkg-config
cd /tmp
git clone --depth=1 --branch v1.4.0 https://github.com/libbpf/libbpf.git
cd libbpf/src/
make -j"$(nproc)"
sudo make install PREFIX=/usr/local LIBDIR=/usr/local/lib
sudo ldconfig
cd ~/monitor
gcc -O2 -Wall -Wextra TEST.c -o TEST
make monitor
sudo ./monitor load
sudo ./monitor run ./TEST
sudo ./monitor unload
```
