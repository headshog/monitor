# Монитор системных вызовов с поддержкой SMACK

eBPF-монитор файловых системных вызовов для Linux. Перехватывает операции с
файлами/каталогами/credentials, выводит по каждому событие в формате JSON и
дополняет его метками безопасности **SMACK** (subject/object labels), снятыми
напрямую из ядерных структур.

Целевое окружение — Ubuntu 22.04, ядро с включённым LSM SMACK,
libbpf ≥ 1.4. Инструкции по сборке — в разделе [Установка](#установка-окружения).

---

## 1. Теоретическая сводка по SMACK

> Источник: <https://www.kernel.org/doc/html/latest/admin-guide/LSM/Smack.html>

**SMACK** (Simplified Mandatory Access Control Kernel) — модуль мандатного
контроля доступа (MAC), реализованный как Linux Security Module (LSM). В
отличие от дискреционного контроля (DAC — обычные `rwx`-права и владельцы),
решение о доступе принимает не владелец объекта, а системная политика на
основе **меток (labels)**.

### Основные понятия

- **Label (метка)** — текстовая строка (до 255 символов), привязанная к
  субъекту или объекту. Примеры предопределённых меток:
  - `_` (floor, «подчёркивание») — системная метка по умолчанию;
  - `^` (hat) — может читать всё;
  - `*` (star) — доступен всем;
  - `?` (huh), `@` (web) — служебные.
- **Subject (субъект)** — активная сущность, выполняющая действие. На практике
  это процесс; его метка хранится в credentials задачи (`task → cred`).
- **Object (объект)** — пассивная сущность, над которой выполняется действие:
  inode файла, каталога, сокета и т.д. Метка хранится в security-блобе inode.

### Как принимается решение о доступе

При каждой файловой операции SMACK сравнивает метку субъекта (процесса) и метку
объекта (inode) по набору **правил доступа** вида:

```
subject_label  object_label  rwxat
```

Если в политике нет явного правила, действуют умолчания:
- субъект с меткой, равной метке объекта, получает полный доступ;
- субъект с меткой `_` (floor) имеет ограниченный доступ;
- иначе — отказ (`EACCES`).

В трассах монитора заблокированная политикой операция выглядит как `ret < 0`
(`EACCES`/`EPERM`), при этом `smack_subj` обычно заполнен, а `smack_obj` может
быть пустым или равным метке проверяемого inode.

### Хранение меток в ядре (важно для монитора)

SMACK размещает свои данные в **LSM-блобах** — областях, выделяемых внутри
ядерных структур `inode`, `cred`, `file` и т.д. Размеры и смещения этих блобов
задаются глобальной структурой `smack_blob_sizes` (тип `struct lsm_blob_sizes`):

- `lbs_inode` — смещение блоба SMACK внутри `inode->i_security`;
- `lbs_cred` — смещение блоба SMACK внутри `cred->security`.

Чтобы прочитать метку объекта, монитор:
1. берёт `inode->i_security` (указатель на массив LSM-блобов);
2. прибавляет смещение `smack_blob_sizes.lbs_inode`;
3. интерпретирует результат как `struct inode_smack`;
4. читает из него `smk_inode` (object label), `smk_task` (exec label),
   `smk_mmap` (mmap label) и `smk_flags`.

Аналогично метка субъекта читается из `cred->security + lbs_cred` как
`struct task_smack → smk_task`.

### Поля SMACK, которые выводит монитор

- `smack_subj` — метка процесса-субъекта (из `cred`);
- `smack_obj` — метка объекта-inode (`smk_inode`);
- `smack_exec` — execute-метка inode (`smk_task`);
- `smack_mmap` — mmap-метка inode (`smk_mmap`);
- `smack_flags` — флаги `inode_smack.smk_flags` (числом);
- `smack_flags_hex` — те же флаги в hex;
- `smack_flags_names` — текстовая расшифровка флагов.

Расшифровка `smack_flags_names`:

| Бит    | Имя                   | Значение                                                    |
|--------|-----------------------|-------------------------------------------------------------|
| `0x01` | `SMK_INODE_INSTANT`   | inode инициализирован SMACK-блобом                          |
| `0x02` | `SMK_INODE_TRANSMUTE` | каталог в режиме transmute                                  |
| `0x04` | `SMK_INODE_CHANGED`   | метка inode изменена через transmute-семантику              |
| `0x08` | `SMK_INODE_IMPURE`    | inode участвовал в impure-транзакции (bringup/debug)        |

Биты вне списка выводятся как `UNKNOWN_BIT_N`.

### Что было сделано по SMACK в этом репозитории

Базовый монитор (коммит `Init`) **не знал про SMACK** — он выводил только
DAC-данные (uid/gid/perms/inode). Поддержка SMACK была добавлена и доведена
серией коммитов:

1. **`Init smack`** — введён весь механизм чтения меток:
   - в `struct syscall_event` добавлены поля `smack_subj/obj/exec/mmap/flags`;
   - в `struct monitor_config` добавлен `smack_blob_sizes_addr`;
   - в BPF появились функции `smack_inode_offset()`, `smack_cred_offset()`,
     `read_smack_label()`, `capture_inode_smack()`, `fill_subject_smack()` и
     структура-снимок `struct smack_snapshot`;
   - реализован **fallback-механизм**: если `smack_blob_sizes` недоступен через
     BTF/`__ksym`, userspace-часть читает адрес символа из `/proc/kallsyms` и
     передаёт его в BPF через `config_map`.
2. **`Update test... All type of operation check`** — захват меток
   распространён на все файловые операции; для операций, где inode исчезает к
   моменту `sys_exit` (`unlink`/`rmdir`/`link`/`symlink`/xattr), добавлены
   kprobe на VFS-функции и `security_*`-хуки, снимающие метку **до** проверки
   доступа.
3. **`Flag names`** — добавлена человекочитаемая расшифровка `smk_flags`
   (`smack_flags_hex`, `smack_flags_names`).
4. **`Fix link`** — добавлены kprobe `security_inode_link` / `security_path_link`,
   чтобы `smack_obj` для `link` снимался до отказа политики (раньше при
   `EACCES` метка терялась).

---

## 2. Обзор изменений относительно коммита `Init`

`Init` — это шаблон-заготовка: eBPF-монитор, который перехватывает базовый набор
файловых syscall'ов и печатает по ним JSON только с DAC-информацией
(uid/gid/inode/perms). За время работы над проектом добавлено следующее.

### Функциональность

| Область                  | Было (`Init`)                                  | Стало                                                                                          |
|--------------------------|------------------------------------------------|-------------------------------------------------------------------------------------------------|
| SMACK-метки              | нет                                            | subject/object/exec/mmap + флаги с расшифровкой, fallback через `/proc/kallsyms`                |
| Набор syscall'ов         | open/openat/creat, mkdir(at), chdir/fchdir, chmod/fchmod, chown/fchown, close, umask, unlink, rmdir, getdents, link, symlink, getxattr/setxattr, execve, exit/exit_group | + `getdents64`, `access`/`faccessat`/`faccessat2`, `linkat`, `unlinkat`, `rename`/`renameat`/`renameat2`, `setuid`/`setgid`/`setreuid`/`setregid`/`setresuid`/`setresgid` |
| Точность для удаляемых объектов | метка терялась (inode уже нет на `sys_exit`) | kprobe на `vfs_*` и `security_*`-хуки снимают метку до операции                                 |
| Корректность `euid`/`egid` | читался `bpf_get_current_uid_gid()` (= real uid) | читается `cred->euid`/`egid`; для `execve` — credentials вызывающего, снятые до setuid-бита    |
| Расшифровка флагов       | нет                                            | `smack_flags_hex` + `smack_flags_names`                                                         |
| Тестовое покрытие        | один `TEST.c`                                  | переработанный `TEST.c` (STEP/CASE/CHECK/SUMMARY) + точечные тесты под отдельные фиксы          |

### Архитектура (неизменное ядро, заложенное в `Init`)

- **`monitor.c`** — userspace-загрузчик. Три команды:
  - `load` — открывает и загружает BPF-скелет, пинит карты/программы/линки в
    `/sys/fs/bpf/anis`, заполняет `config_map`;
  - `run <cmd>` — включает мониторинг, форкает целевую программу, читает
    события из ring buffer и печатает JSON через `handle_event()`;
  - `unload` — снимает пины.
- **`syscall_monitor.bpf.c`** — BPF-программы (tracepoints на enter/exit
  syscall'ов + kprobe/kretprobe на VFS-функции).
- **`syscall_monitor.h`** — общий ABI: `struct syscall_event` (union по типам
  syscall'ов) и `struct monitor_config`.
- **`utils.h`** — BPF-хелперы (`bpf_get_path`, чтение xattr, `bpf_get_task_file`).
- **фильтрация** — по умолчанию монитор реагирует только на процессы с префиксом
  имени `tst_` (`filter_tst` в `config_map`), чтобы не тонуть в системном шуме.

---

## Установка окружения

### Образ

1. Ставим с <https://releases.ubuntu.com/22.04> «Desktop image for 64-bit PC
   (AMD64) computers (standard download)».
2. Маунтим shared-директорию с монитором, либо копируем в хомяк.
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

### Включение SMACK

```bash
sudo cp /etc/default/grub /etc/default/grub.bak.$(date +%F-%H%M)
sudo vim /etc/default/grub
# В файл:
# GRUB_CMDLINE_LINUX="lsm=landlock,lockdown,yama,integrity,smack security=smack apparmor=0"
sudo update-grub
sudo reboot
# После ребута проверить:
cat /sys/kernel/security/lsm
bpftool btf dump file /sys/kernel/btf/vmlinux format raw | rg -n '\bsmack_blob_sizes\b'
sudo sysctl kernel.kptr_restrict=0
sudo grep -w smack_blob_sizes /proc/kallsyms
# Адрес должен быть не 0000000000000000
```

Если символ `smack_blob_sizes` не найден или адрес скрыт
(`0000000000000000`), поля `smack_*` останутся пустыми.

---

## Разбор вывода теста `TEST.c`

`TEST` печатает строки двух типов: служебные строки теста и JSON-события
монитора.

### Служебные строки теста

- `CASE_<NAME> START/END` — границы логического блока (setup/create/access/
  rename/listdir/delete/cleanup).
- `STEP <ID>` + `TESTS/EXPECT` — что проверяется и какие syscall'ы ожидаются.
- `CHECK PASS <op> ret=<v>` — операция успешна (`mkdir ret=0`, `open ret=3`).
- `CHECK SKIP <op> ret=<v> errno=...` — операция пропущена как ожидаемое
  ограничение среды (`EPERM` для link/symlink, `EOPNOTSUPP` для xattr,
  `EINVAL` для renameat2, `ENOENT` при удалении несозданных ссылок).
- `CHECK FAIL <op> ...` — неожиданная ошибка (считается ошибкой теста).
- `SUMMARY total=... failed=... skipped=... passed=...` — итог.
- `REQ_ACCESS/REQ_CREATE/REQ_DELETE_RENAME/REQ_LISTDIR` — покрытие 4 групп
  событий: доступ к объекту, создание файла/жёсткой ссылки, удаление/
  переименование, чтение содержимого каталога.

### JSON-события монитора

Каждая JSON-строка — событие из eBPF-монитора: `syscall`, `ret`, `smack_*` и
поля, специфичные для конкретного syscall'а. Порядок `CHECK` и JSON может
немного отличаться — события приходят асинхронно через ring buffer.

### Как выглядит блокировка SMACK

Заблокировано: `ret < 0` (`EACCES`/`EPERM`), `smack_subj` заполнен,
`smack_obj` может быть пустым, в тесте — `CHECK SKIP`/`CHECK FAIL`.
Разрешено: `ret == 0` (или `ret >= 0` для open/getdents), `smack_obj`
обычно непустой, `smack_flags` ненулевой.

---

## 3. Покоммитная сводка основных изменений

История ведётся от `Init` (шаблон) к актуальному состоянию.

### `Init` — базовый шаблон монитора
Первая рабочая версия: `monitor.c` (load/run/unload, пиннинг в
`/sys/fs/bpf/anis`, ring buffer, `handle_event`), `syscall_monitor.bpf.c` с
tracepoints на enter/exit базового набора файловых syscall'ов и kprobe на
`chmod_common`/`chown_common`/`vfs_mkdir`, общий ABI в `syscall_monitor.h`,
хелперы в `utils.h`, базовый `TEST.c`, `Makefile`, `INSTALL`. **SMACK ещё нет** —
выводятся только DAC-поля.

### `Init smack` — введение поддержки SMACK
Добавлен весь механизм чтения меток безопасности:
- в `struct syscall_event` — поля `smack_subj/obj/exec/mmap/flags`;
- в `struct monitor_config` — `smack_blob_sizes_addr`;
- BPF-функции `smack_inode_offset()`, `smack_cred_offset()`,
  `read_smack_label()`, `capture_inode_smack()`, `fill_subject_smack()`,
  `struct smack_snapshot`;
- `extern struct lsm_blob_sizes smack_blob_sizes __ksym __weak` + fallback на
  адрес из `/proc/kallsyms`, передаваемый через `config_map`;
- инструкция по включению SMACK в README;
- закоммичен `bpf_dump` (дамп BTF для отладки смещений).

### `Update test. Monitor refactor. All type of operation check`
Крупный коммит, расширивший покрытие:
- добавлены syscall'ы `getdents64`, `access`/`faccessat`/`faccessat2`,
  `linkat`, `unlinkat`, `rename`/`renameat`/`renameat2`;
- для операций, где inode исчезает к `sys_exit`, добавлены kprobe/kretprobe на
  `vfs_unlink`/`vfs_rmdir`/`vfs_link`/`vfs_symlink`/`vfs_getxattr`/`vfs_setxattr`
  и `security_*`-хуки, снимающие метку объекта до проверки доступа;
- введены per-syscall карты-снимки SMACK (`*_smack_map`) и контекст-карты для
  обработки вложенных VFS-вызовов (depth-счётчик);
- переработан `TEST.c` под формат STEP/CASE/CHECK/SUMMARY с группами требований
  `REQ_*`;
- в `syscall_monitor.h` добавлены структуры под новые syscall'ы.

### `Flag names`
Человекочитаемая расшифровка флагов SMACK: `smack_flags_hex` и
`smack_flags_names` (`SMK_INODE_INSTANT`, `_TRANSMUTE`, `_CHANGED`, `_IMPURE`,
неизвестные биты как `UNKNOWN_BIT_N`). Реализованы хелперы
`append_flag_name()` / `format_smack_flags_names()` в `monitor.c`.

### `Add test and fix for execve`
- Исправлен баг `execve`: на `sys_enter` имя процесса (`comm`) ещё старое, и
  фильтр `tst_` отбрасывал событие. Аргументы execve теперь сохраняются
  безусловно, а фильтрация делается на `sys_exit` по новому `comm`.
- Добавлен `test_creat.c`.

### `Fix link`
- Добавлены kprobe `security_inode_link` и `security_path_link`: метка объекта
  (исходного файла) для `link`/`linkat` снимается **до** проверки доступа, так
  что `smack_obj` заполняется даже при отказе политики (`EACCES`).
- `apply_smack_from_map(...)` для link/linkat вызывается безусловно (метка
  осмысленна и при `ret < 0`).
- Добавлен `test_korn.c`.

### `Fix euid` (первый)
Исправлено главное поле идентификации: вместо `bpf_get_current_uid_gid()`
(который возвращает **real** uid/gid) `euid`/`egid` читаются напрямую из
`cred->euid`/`cred->egid` через CO-RE. Раньше для setuid-бинарей в трассе был
неверный пользователь. Добавлены `test_get_uid.c`, `test_uid.c`.

### `Fix euid` (второй) — credentials для execve + set*id syscalls
- Для `execve` `euid`/`egid` теперь берутся из credentials **вызывающего**,
  снятых на `sys_enter` (до `commit_creds` с setuid-битом бинаря), через
  отдельную карту `execve_caller_creds_map`. Иначе событие execve setuid-root
  бинаря показывало root вместо реального запускающего пользователя.
- Добавлен парсинг syscall'ов смены идентификаторов:
  `setuid`/`setgid`/`setreuid`/`setregid`/`setresuid`/`setresgid` (BPF
  tracepoints, поля в `syscall_monitor.h`, case'ы в `handle_event`).
- Добавлен `test_setuid.c`.
