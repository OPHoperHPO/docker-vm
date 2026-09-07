# Pre-baked VM Docker images

Три Docker-образа с уже встроенной ОС и init-скриптами. Под капотом —
QEMU/KVM (`qemux/qemu`, `dockurr/windows`, `dockurr/macos`).

| Образ | ОС | Размер |
|---|---|---|
| `ghcr.io/<you>/<repo>-ubuntu-24.04` | Ubuntu 24.04 cloud image | ~1 GB |
| `ghcr.io/<you>/<repo>-windows-11` | Windows 11 IoT LTSC | ~6.3 GB |
| `ghcr.io/<you>/<repo>-macos` | macOS (recovery вшит в образ) | ~1.5 GB |

Никаких скачиваний при первом старте — ISO/qcow2/dmg уже внутри образа.

Плюс к этому:

* **[Ограничение доступа VM к сети](docs/network.md)** — правила по подсетям и
  портам, которые применяются снаружи гостя, без `NET_ADMIN` и без iptables на
  хосте.
* **Не залипает после падения passt** — сторож перезапускает контейнер, если
  сетевой хелпер умер, вместо VM без сети, которую надо заметить руками.
* Лимит открытых файлов поднимается сам, до того как стартует passt.

---

## Структура

```
.
├── .github/workflows/build.yml      # CI: matrix-сборка → push в GHCR
├── docs/network.md                  # ⇐ правила доступа к сети
├── examples/compose.yml             # готовый compose на три VM
├── shared/
│   ├── hooks/                       # общие для всех образов startup-хуки
│   │   ├── start.sh                 #   лимит fd + /run/hooks.d/*
│   │   ├── network.sh               #   обёртка над сетью базового образа
│   │   ├── guard.sh                 #   подключение vmguard
│   │   └── watchdog.sh              #   сторож за passt/vmguard
│   └── vmguard/                     # фильтр трафика (Go, без зависимостей)
└── images/
    ├── ubuntu/
    │   ├── Dockerfile               # Бакает cloud-image и cloud-init seed
    │   ├── hooks/10-stage-image.sh  # копирует qcow2 в /storage на 1-м запуске
    │   └── cloud-init/
    │       ├── user-data            # ⇐ редактируй это
    │       └── meta-data
    ├── windows/
    │   ├── Dockerfile               # Бакает Win11 ISO + /oem
    │   └── oem/
    │       ├── install.bat          # ⇐ запускается на 1-м логине
    │       └── firstboot.ps1        # ⇐ сюда логику инициализации
    └── macos/
        ├── Dockerfile               # Бакает recovery-образ Apple
        ├── fetch-recovery.sh        # скачивание и проверка recovery на сборке
        └── hooks/10-macos.sh
```

Все Dockerfile собираются **из корня репозитория**, потому что используют
общий `shared/`:

```bash
docker build -f images/ubuntu/Dockerfile -t ubuntu-vm .
```

---

## Запуск

Минимум привилегий: единственное обязательное устройство — `/dev/kvm`.

```yaml
services:
  ubuntu:
    image: ghcr.io/<you>/<repo>-ubuntu-24.04:latest
    restart: always
    stop_grace_period: 2m
    devices:
      - /dev/kvm
    volumes:
      - ./ubuntu-storage:/storage
    ports:
      - 127.0.0.1:8006:8006     # web-консоль
      - 127.0.0.1:2222:22       # ssh в VM
    environment:
      CPU_CORES: 8
      RAM_SIZE: 16G
      DISK_SIZE: 150G
      USER_PORTS: "22"          # какие порты VM пробросить наружу
```

Полный пример на три VM — [`examples/compose.yml`](examples/compose.yml).

`NETWORK=passt` и `DNSMASQ_DISABLE=Y` — уже дефолт образов, отдельно задавать
не нужно. `ulimits` в compose тоже не нужен: soft-лимит поднимается сам до
hard-лимита при старте.

### docker run

```bash
docker run -d --name ubuntu-vm \
  --restart=always \
  --device=/dev/kvm \
  -p 127.0.0.1:8006:8006 \
  -v ./ubuntu-storage:/storage \
  ghcr.io/<you>/<repo>-ubuntu-24.04:latest
```

Первый запуск Ubuntu — ~30 секунд до готовности cloud-init.
Первый запуск Windows — ~10–15 минут unattended-инсталляции (с диска, не из сети).
SSH/RDP по умолчанию: `ubuntu/ubuntu`, `Docker/admin`.

---

## Ограничение доступа к сети

```yaml
environment:
  NET_PRESET: internet        # интернет можно, домашнюю сеть и соседей — нет
```

```yaml
environment:
  NET_POLICY: deny            # по умолчанию всё запрещено
  NET_ALLOW: >-
    tcp:archive.ubuntu.com:80,443
    tcp:ghcr.io:443
    tcp:10.10.0.5:5432
```

Правила применяются между QEMU и passt, то есть **снаружи гостевой ОС**:
внутри VM их не видно и отключить их оттуда нельзя. Хосту не нужны ни
`NET_ADMIN`, ни `/dev/net/tun`, ни правила файрвола.

Заблокированное TCP-соединение обрывается сразу (`RST`), а не висит до
таймаута. Заблокированные потоки видны в логах контейнера и в JSON-статусе.

Подробности, синтаксис, пресеты, живая перезагрузка правил из файла —
[`docs/network.md`](docs/network.md).

---

## Инициализация

### Ubuntu

Редактируй `images/ubuntu/cloud-init/user-data`. Релевантные секции:

```yaml
runcmd:
  - [ /opt/firstboot.sh ]   # отсюда вызывается твой скрипт

write_files:
  - path: /opt/firstboot.sh
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      # ВОТ СЮДА твою логику
```

cloud-init выполнится **один раз** на свежем диске. Чтобы пере-запустить —
удали `./ubuntu-storage` и перезапусти контейнер.

### Windows

Редактируй `images/windows/oem/firstboot.ps1` (PowerShell) или
`images/windows/oem/install.bat`. Файлы попадают в `C:\OEM\` внутри Windows,
`install.bat` запускается автоматически на первом логине через встроенный
FirstLogonCommand в дефолтном unattend XML.

Логи — `C:\OEM\install.log`.

После любого изменения init-скриптов нужно пересобрать образ
(workflow триггернётся на push) и удалить storage-volume для re-run.

### macOS

Recovery-образ Apple скачивается и проверяется **на сборке** и лежит внутри
контейнера; при первом старте он раскладывается в `/storage/<версия>/base.dmg`,
поэтому установщик поднимается сразу — без ожидания серверов Apple.

Дальше несколько шагов делаются в web-консоли (порт 8006) руками:

1. выбрать язык;
2. **Disk Utility** → выбрать самый большой диск QEMU → **Erase**
   (имя `Macintosh HD`, формат `APFS`, схема `GUID Partition Map`);
3. выйти из Disk Utility → **Reinstall macOS** → дальше по мастеру.

Unattended-режима у установщика macOS не существует — ни `startosinstall`,
ни Setup Assistant не умеют работать без GUI, поэтому эти шаги остаются
ручными во всех проектах такого рода. Контейнер печатает эту инструкцию
в лог при первом запуске.

Всё, что установлено, живёт в примонтированном `/storage` и переживает
перезапуски.

Версия macOS задаётся на сборке:

```bash
docker build -f images/macos/Dockerfile \
  --build-arg MACOS_VERSION=14 -t macos-vm .
```

Apple пускает на `osrecovery.apple.com` не из всякой сети. Что делать в этом
случае, выбирает `--build-arg BAKE_RECOVERY`:

| Значение | Поведение |
|---|---|
| `auto` (по умолчанию) | попробовать вшить; если Apple отказал — предупредить и оставить скачивание на первый старт |
| `Y` | вшить обязательно, иначе сборка падает |
| `N` | не вшивать, качать при первом старте (как в оригинальном `dockurr/macos`) |

В любом случае контейнер в логе при старте пишет, какой образ он использует.

macOS требует Intel-совместимый профиль CPU; на AMD-хостах образ выбирает его
сам. Меньше 8 GB RAM и 4 ядер ставить не стоит.

---

## Режимы сети

| `NETWORK=` | Привилегии | Когда использовать |
|---|---|---|
| `passt` (дефолт) | `/dev/kvm` | Всегда, если нет причин для другого |
| `slirp` | `/dev/kvm` | Если passt падает (старое ядро) |
| `tap` | `+ NET_ADMIN, /dev/net/tun` | Нужна максимальная пропускная способность |
| `DHCP=Y` (macvlan) | `+ NET_ADMIN, vhost-net, cgroup rules` | VM нужен свой IP в LAN роутера |

Порты VM наружу: либо `USER_PORTS="22,80,443"` (явный список), либо
`PASST_OPTS="-t all -u all"` (все).

Правила доступа (`docs/network.md`) работают только в режиме `passt`. Если
правила заданы, а режим другой — контейнер откажется стартовать, а не сделает
вид, что ограничения действуют.

---

## CI / GHCR

Workflow `Build VM images`:

* собирает все три образа и **пушит в GHCR только с дефолтной ветки**;
* на любой другой ветке и в PR собирает полностью, но ничего не публикует —
  ветка не может залить недоделанный образ в package registry;
* перед сборкой гоняет тесты `vmguard` — юнит-тесты, тесты с реальным `passt`
  внутри `qemux/qemu`, `shellcheck` по хукам.

Ручной запуск с переопределениями:

```bash
gh workflow run "Build VM images" -f targets=macos -f macos_version=14
gh workflow run "Build VM images" -f targets=windows \
  -f win_iso_url='https://software-static.download.prss.microsoft.com/.../...iso' \
  -f win_iso_sha256='<sha256>'
```

Опубликовать образы из не-дефолтной ветки можно только явно:
`-f push_images=true`.

URL+hash для других редакций Windows смотри в
[`dockur/windows/src/define.sh`](https://github.com/dockur/windows/blob/master/src/define.sh)
(функция `getMido`). Когда дефолтный URL стухнет (Microsoft меняет билды раз
в 3–6 месяцев), sha256 не сойдётся и CI это покажет.

Permissions: репо → Settings → Actions → General → "Read and write
permissions" для `GITHUB_TOKEN`.

---

## Требования к хосту

- Linux + `/dev/kvm` (KVM включён в BIOS, ядро не блокирует).
- ~10 GB свободного диска под Windows storage volume (sparse qcow2 64 GB),
  ~100 GB под macOS.
- Не работает на cloud VPS без nested virt (большинство — без).

Полный список env-переменных:
[qemus/qemu](https://github.com/qemus/qemu),
[dockur/windows](https://github.com/dockur/windows),
[dockur/macos](https://github.com/dockur/macos).
