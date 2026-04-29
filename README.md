# Инструкция по установке окружения

## Образ

1. Ставим с https://releases.ubuntu.com/22.04 "Desktop image for 64-bit PC (AMD64) computers (standard download)".

2. Маунтим shared директорию с монитором, либо копируем в хомку, кому как удобно.

3. В консоли после установки:

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
- `smack_flags_hex` — то же значение флагов в hex
- `smack_flags_names` — текстовые имена установленных флагов (`SMK_INODE_*`)

Расшифровка `smack_flags_names`:
- `SMK_INODE_INSTANT` (`0x01`) — inode инициализирован Smack-блобом;
- `SMK_INODE_TRANSMUTE` (`0x02`) — каталог в режиме transmute;
- `SMK_INODE_CHANGED` (`0x04`) — метка inode была изменена через transmute-семантику;
- `SMK_INODE_IMPURE` (`0x08`) — inode отмечен как участвовавший в impure-транзакции (bringup/debug сценарии).

Если в значении встречаются биты вне списка, монитор выводит их как `UNKNOWN_BIT_N`.

Если в `bpftool btf dump ...` нет `smack_blob_sizes`, монитор использует fallback:
читает адрес символа `smack_blob_sizes` из `/proc/kallsyms` и передаёт его в BPF через `config_map`.

Проверьте:
```bash
cat /sys/kernel/security/lsm
grep -w smack_blob_sizes /proc/kallsyms
```

Если символ не найден или адрес скрыт (`0000000000000000`), `smack_*` поля останутся пустыми.

## Разбор вывода теста

`TEST` печатает два типа строк:
- служебные строки теста (`STEP`, `CASE`, `CHECK`, `SUMMARY`, `REQ_*`);
- JSON-события монитора (строки с полями `syscall`, `smack_*`, `ret` и т.д.).

### Служебные строки теста

- `CASE_<NAME> START/END`  
  Границы логического блока теста (setup/create/access/rename/listdir/delete/cleanup).

- `STEP <ID>` + `TESTS/EXPECT`  
  Что именно проверяется в текущем шаге и какие syscall ожидаются в логе монитора.

- `CHECK PASS <operation> ret=<value>`  
  Операция выполнена успешно по критерию шага.  
  Примеры:
  - `mkdir ... ret=0` — каталог создан;
  - `open ... ret=3` — успешно получен файловый дескриптор `3` (`ret >= 0`).

- `CHECK SKIP <operation> ret=<value> errno=...`  
  Операция пропущена как ОЖИДАЕМОЕ ограничение среды (не считается ошибкой теста).  
  В этом проекте обычно:
  - `EPERM` для `link/linkat/symlink` (ограничение политики);
  - `EOPNOTSUPP` для `setxattr/getxattr` (xattr не поддержан в текущем окружении);
  - `EINVAL` для `renameat2` (конкретная комбинация не поддержана);
  - `ENOENT` при удалении ссылок, если они не были созданы.

- `CHECK FAIL <operation> ...`  
  Неожиданная ошибка шага (считается ошибкой теста).

- `SUMMARY total=... failed=... skipped=... passed=...`  
  Итог по всем шагам теста.

- `REQ_ACCESS/REQ_CREATE/REQ_DELETE_RENAME/REQ_LISTDIR`  
  Покрытие 4 требуемых групп событий:
  - доступ к существующему объекту;
  - создание файла/жесткой ссылки;
  - удаление/переименование;
  - чтение содержимого директории.

### JSON-события монитора

Каждая JSON-строка — событие из eBPF-монитора:
- `syscall` — системный вызов;
- `ret` — результат syscall (0 или `>=0` обычно успех, `<0` ошибка);
- `smack_subj` — метка процесса;
- `smack_obj`/`smack_exec`/`smack_mmap`/`smack_flags` — метки и флаги объекта inode.

Примечание: порядок `CHECK` и JSON может слегка отличаться, так как события приходят через ring buffer.

### Как выглядит блокировка SMACK в выводе

Если операцию блокирует политика SMACK, в логе обычно видно:
- в событии syscall `ret < 0` (в тесте это часто `ret=-1` + `errno=EACCES/EPERM`);
- `smack_subj` обычно заполнен (кто выполнял действие);
- `smack_obj` может быть пустым (`""`) на части путей;
- `smack_flags` часто `0`;
- в служебном выводе теста шаг будет `CHECK SKIP` (если этот errno ожидается) или `CHECK FAIL` (если не ожидался).

Если операция не заблокирована:
- `ret == 0` (или `ret >= 0` для `open/getdents`);
- для файловых операций обычно есть непустой `smack_obj` (например `_`);
- `smack_flags` обычно ненулевой (например `1`).

Пример интерпретации:
- разрешено: `rename ... ret: 0`, `smack_obj: "_"`;
- заблокировано: `link ... ret: -1`, `errno=EPERM`, `smack_obj: ""`.
