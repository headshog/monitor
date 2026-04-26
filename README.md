# Инструкция по установке окружения

## Образ

1. Ставим с https://releases.ubuntu.com/22.04 "Desktop image for 64-bit PC (AMD64) computers (standard download)".

2. Маунтим shared директорию с монитором, либо копируем в хомку, кому как удобно.

2. В консоли после установки:

```bash
sudo apt update
sudo apt upgrade
sudo apt install -y clang libbpf-dev make linux-tools-common linux-tools-generic pkgconf build-essential clang llvm libelf-dev zlib1g-dev git make pkg-config ripgrep
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

## Включение Smack

```bash
sudo cp /etc/default/grub /etc/default/grub.bak.$(date +%F-%H%M)
sudo vim /etc/default/grub
# В файл
#GRUB_CMDLINE_LINUX="lsm=landlock,lockdown,yama,integrity,smack security=smack apparmor=0"
sudo update-grub
sudo reboot
#После ребута проверить:
cat /sys/kernel/security/lsm
bpftool btf dump file /sys/kernel/btf/vmlinux format raw | rg -n '\bsmack_blob_sizes\b'
sudo sysctl kernel.kptr_restrict=0
sudo grep -w smack_blob_sizes /proc/kallsyms
# Должно быть не 0000000000000000
```

## Smack-поля в событии

Для файловых syscall в JSON теперь выводятся поля:
- `smack_subj` — метка процесса (subject)
- `smack_obj` — метка объекта inode
- `smack_exec` — execute label inode
- `smack_mmap` — mmap label inode
- `smack_flags` — флаги `inode_smack.smk_flags`

Если в `bpftool btf dump ...` нет `smack_blob_sizes`, монитор использует fallback:
читает адрес символа `smack_blob_sizes` из `/proc/kallsyms` и передаёт его в BPF через `config_map`.

Проверьте:
```bash
cat /sys/kernel/security/lsm
grep -w smack_blob_sizes /proc/kallsyms
```

Если символ не найден или адрес скрыт (`0000000000000000`), `smack_*` поля останутся пустыми.
