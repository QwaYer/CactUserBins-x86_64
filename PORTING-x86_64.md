# План работ: CactUserBins x86_64 (CactOS 3.0.0)

Форк от `2.0.0` (i686). `MAJOR` → 3 по правилу «`MAJOR` = смена архитектурного
поколения»: все утилиты перелинковываются под ABI ядра 3.0.0 и libc 3.0.0
(`CactKernel-x86_64`, `CactLibc-x86_64`, решения 5/9 ядра, решение 5 libc).

Этот файл — план, а не обещание. Инвентарь снят по коду; при расхождении верить
коду.

## Что это за репозиторий

Не дерево исходников, а **плоский набор**: по одной программе на каталог
(`<tool>/main.c`), общие реализации — в `common/` (24 объекта `ex_*.c`), плюс три
host-инструмента для подготовки образов (`fdisk`, `mkfs.ext4`, `mkfs.fat32`,
`cact-rootfs`). Одно `foreach` в `meson.build` собирает по одной PIE на
инструмент из списков `apps`/`sbin_apps`; `firmextr` дополнительно линкует zstd.

Зависимости сборки — все уже портированы: `CactLibc-x86_64` (`start.o`,
`clibc.so`), `Cactsole-x86_64` (`include/` — общий `shell.h` для bridge-утилит
`cd`/`export`/`unset`/`exit`/`jobs`/`fg`/`bg`/`help`), а DRM-uapi и zstd берутся
из `CactKernel-x86_64`.

## Инвентарь 32-битных поверхностей

- `cross/i686-cact-clang.ini` — `-m32`, `cpu_family=x86`, `cpu=i686`.
- `meson.build` — линковка `ld -m elf_i386 -pie`; заголовочный комментарий
  ссылается на `cross/i686-cact-clang.ini` и `../Cact*-x86_32`. **Host-инструменты**
  (`executable(..., native: true)`) собираются `-m32` (`host_c_args`,
  `host_link_args`) — это бинарники сборочной машины, им нужен `-m64`.
- `link.ld` — секции `.rel.dyn`/`.rel.plt` (в x86_64 — `.rela.*`); нет
  `.data.rel.ro`. База `0x08000000` не двигается (решения 5/9 ядра).
- `meson_options.txt` — шесть путей по умолчанию: `cactlib`, `cactsoleinc`,
  `lr_bin`, `lr_sbin`, `drmuapi`, `zstd_dir` — все `../*-x86_32/...`.
- `README.md` — бейдж `i686`, ссылки `*-x86_32`, `LocalRepoCactOS-x86_32`.

## Решения

1. **Тулчейн как у соседей.** `cross/x86_64-cact-clang.ini` (`-m64`,
   `cpu_family=cpu=x86_64`), `ld -m elf_x86_64`, дефолты `meson_options.txt` →
   `../*-x86_64` (`cactlib`, `cactsoleinc`, `lr_bin`, `lr_sbin`, `drmuapi`,
   `zstd_dir`).
2. **Host-инструменты — `-m64`.** `host_c_args`/`host_link_args` были `-m32`
   только потому, что сборочная машина тоже i386; на x86_64 хост и цель
   совпали, и бинарник сборочной машины собирается нативно.
3. **База фиксированной линковки `0x08000000` не двигается** (решение 5 libc).
4. **Скрипт линковки под ELF64.** Добавляются `.rela.dyn`/`.rela.plt` и
   `.data.rel.ro`; пара `.rel.*` остаётся против orphan-секций.
5. **C-код ширинонезависим, но проверяется сборкой всех 123.** Отдельного
   `VERSION`/`version.h` у репозитория нет.

## Этапы

### Фаза 0 — тулчейн

`cross/x86_64-cact-clang.ini`; `meson.build` (`elf_x86_64`, `-m64` у host,
комментарии); `link.ld`; `meson_options.txt`; `README.md`.

**Milestone:** `ninja -C build-meson` собирает все инструменты; `readelf -h`
одного из них — `ELF64`/`EM_X86_64`.

### Фаза 1 — сборка всех 123 и починка ширин

Прогон полной сборки; по каждому падению — разбор, шириночувствителен ли код
(указатель, приведённый к `int`/`u32`, разъезд `long` с `size_t`, формат
`printf`). Правки — точечные, по инструменту.

**Milestone:** `ninja -C build-meson` без ошибок компиляции; у каждого бинарника
`readelf -r` — только поддерживаемые релокации (решение 4 libc).

### Фаза 2 — stage и host-инструменты

`ninja -C build-meson stage` в каталоги `lr_bin`/`lr_sbin`; сборка host-наборов
(`host-fdisk`, `host-mkfs.ext4`, `host-mkfs.fat32`, `host-cact-rootfs`).

**Milestone:** `stage` раскладывает `bin`/`sbin` куда сказано;
`ninja -C build-meson host-mkfs.ext4` собирается нативно.

## Проверки

- **Кросс-сборка** — `meson setup build-meson --cross-file
  cross/x86_64-cact-clang.ini -Dcactlib=../CactLibc-x86_64
  -Dcactsoleinc=../Cactsole-x86_64/include && ninja -C build-meson`.
- **Заголовок и релокации** — `readelf -h`/`readelf -r` по нескольким бинарникам.
- **Host-инструменты** — `ninja -C build-meson host-mkfs.ext4` и пр.
- **На железе/в QEMU** — за ядром: `cactsole` делает `execve` утилит по `PATH`.

## Открытые вопросы

- **`tests/` пуст** — в чекауте нет `run_tests.sh`, харнесс отсутствует; сборка
  здесь — единственная проверка.
- **Шириночувствительность C-кода** — 124 `main.c` + 24 `common/*.c`; правится
  по факту ошибок сборки (Фаза 1), а не рассуждением.
- **Образ — `ET_EXEC`, а не `ET_DYN`** (как у cactsole/cgoct 2.0.0): ядро мапит
  по `PT_LOAD` без проверки `e_type`.
