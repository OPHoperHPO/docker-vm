# Pre-baked VM Docker images

Три Docker-образа с уже встроенной ОС и init-скриптами. Под капотом — QEMU/KVM
(`qemux/qemu`, `dockurr/windows`, `dockurr/macos`).

| Образ | ОС | Размер |
|---|---|---|
| `ghcr.io/<you>/<repo>-ubuntu-24.04` | Ubuntu 24.04 cloud image | ~2 GB |
| `ghcr.io/<you>/<repo>-windows-11` | Windows 11 IoT LTSC | ~6 GB |
| `ghcr.io/<you>/<repo>-macos` | macOS 15 (recovery внутри) | ~1.5 GB |

Размеры распакованные — почти целиком это вшитый образ ОС. Первый старт не
ходит в сеть за операционкой: qcow2, ISO и recovery уже лежат внутри.

Плюс к этому:

* **[Ограничение доступа VM к сети](docs/network.md)** — правила по подсетям и
  портам, применяются снаружи гостя, без `NET_ADMIN` и без iptables на хосте.
* **Не залипает после падения passt** — сторож перезапускает контейнер, если
  сетевой хелпер умер, вместо VM без сети, которую надо заметить руками.
* Лимит открытых файлов поднимается сам, до того как стартует passt.

---

## Запуск

Единственное обязательное устройство — `/dev/kvm`.

```yaml
services:
  ubuntu:
    image: ghcr.io/<you>/<repo>-ubuntu-24.04:latest
    restart: always
    stop_grace_period: 2m
    devices: [ /dev/kvm ]
    volumes:
      - ./storage/ubuntu:/storage
    ports:
      - 127.0.0.1:8006:8006     # web-консоль
      - 127.0.0.1:2222:22       # ssh внутрь VM
    environment:
      CPU_CORES: 4
      RAM_SIZE: 8G
      DISK_SIZE: 64G
      USER_PORTS: "22"          # какие порты VM пробросить наружу
      NET_PRESET: internet      # интернет можно, приватные сети — нет
```

Готовый пример на все три VM — [`examples/compose.yml`](examples/compose.yml).

`NETWORK=passt` и `DNSMASQ_DISABLE=Y` уже дефолт образов, задавать не нужно.
`ulimits` в compose тоже не нужен: soft-лимит поднимается сам до hard-лимита.

### Как заходить внутрь

| VM | Доступ | Учётка |
|---|---|---|
| Ubuntu | SSH на проброшенный порт | `ubuntu` / `ubuntu` |
| Windows | RDP на 3389 | `Docker` / `admin` |
| macOS | web-консоль или VNC 5900 | заводится при установке |

**SSH из коробки есть только у Ubuntu.** В Windows его нет вообще, в macOS
Remote Login выключен, пока не включишь его в System Settings.

У всех трёх есть web-консоль на порту 8006 внутри контейнера — она показывает
экран VM и нужна тогда, когда сети внутри ещё нет.

Первый старт: Ubuntu — меньше минуты до готовности cloud-init, Windows —
10–15 минут unattended-установки с вшитого ISO, macOS — см. ниже.

---

## Ограничение доступа к сети

```yaml
environment:
  NET_PRESET: internet        # всё, кроме приватных сетей и cloud-metadata
```

```yaml
environment:
  NET_POLICY: deny            # по умолчанию всё запрещено
  NET_ALLOW: >-
    tcp:archive.ubuntu.com:80,443
    tcp:ghcr.io:443
    tcp:10.10.0.5:5432
```

Правила применяются между QEMU и passt, то есть **снаружи гостевой ОС**: внутри
VM их не видно и отключить их оттуда нельзя. Хосту не нужны ни `NET_ADMIN`, ни
`/dev/net/tun`, ни правила файрвола.

Правила описывают, кому можно *начинать* разговор: ответы на уже разрешённое
соединение проходят, поэтому проброшенный внутрь SSH работает и при запрете
приватных сетей. Заблокированное TCP-соединение обрывается сразу (`RST`), а не
висит до таймаута; заблокированные потоки видны в логах контейнера.

Синтаксис, пресеты, файл правил с перечиткой на лету, статус-эндпоинт —
[`docs/network.md`](docs/network.md).

---

## Инициализация

### Ubuntu

Редактируй `images/ubuntu/cloud-init/user-data`:

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

cloud-init выполняется **один раз** на свежем диске. Чтобы прогнать заново —
удали каталог storage и перезапусти контейнер.

### Windows

Редактируй `images/windows/oem/firstboot.ps1` (PowerShell) или
`images/windows/oem/install.bat`. Файлы попадают в `C:\OEM\`, `install.bat`
запускается автоматически на первом логине — за это отвечает FirstLogonCommand
в дефолтном unattend XML, свой писать не нужно.

Логи — `C:\OEM\install.log`.

После правки init-скриптов пересобери образ и удали storage, иначе они не
отработают повторно.

### macOS

Recovery-образ Apple скачивается на сборке и сверяется с подписанным
chunklist'ом Apple: SHA-256 по каждому куску, подпись проверяется ключом Apple
EFI ROM. При первом старте он раскладывается в `/storage/<версия>/base.dmg`,
поэтому установщик поднимается сразу.

Дальше три шага делаются в web-консоли руками:

1. выбрать язык;
2. **Disk Utility** → выбрать самый большой диск QEMU → **Erase**
   (имя `Macintosh HD`, формат `APFS`, схема `GUID Partition Map`);
3. выйти из Disk Utility → **Reinstall macOS** → дальше по мастеру.

Unattended-режима у установщика macOS не существует: ни `startosinstall`, ни
Setup Assistant не работают без GUI. Контейнер печатает эту инструкцию в лог
при первом запуске. Всё установленное живёт в `/storage` и переживает
перезапуски.

Версия задаётся на сборке:

```bash
docker build -f images/macos/Dockerfile --build-arg MACOS_VERSION=14 -t macos-vm .
```

Apple пускает на `osrecovery.apple.com` не из всякой сети. Что делать в этом
случае, выбирает `--build-arg BAKE_RECOVERY`:

| Значение | Поведение |
|---|---|
| `auto` (по умолчанию) | попробовать вшить; если Apple отказал — предупредить и оставить скачивание на первый старт |
| `Y` | вшить обязательно, иначе сборка падает |
| `N` | не вшивать, качать при первом старте (как в оригинальном `dockurr/macos`) |

Контейнер в логе при старте пишет, какой образ он использует.

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

Порты VM наружу задаёт `USER_PORTS="80,443"`. Порт 22 (в Windows — 3389 по TCP
и UDP) пробрасывается по умолчанию, `USER_PORTS` добавляется к нему, а порт
web-консоли занят контейнером и в список не попадает.

Можно описать проброс целиком самому через `PASST_OPTS` с `-t`/`-u` — тогда
образ свои порты для этого протокола не добавляет и не мешает. Только учти, что
`-t all` — это около 32 тысяч сокетов: на контейнере с низким лимитом
дескрипторов passt откажется стартовать.

Правила доступа работают только в режиме `passt`. Если правила заданы, а режим
другой — контейнер откажется стартовать, а не сделает вид, что ограничения
действуют.

---

## Структура

```
.
├── .github/
│   ├── workflows/build.yml          # CI: сборка матрицей → push в GHCR
│   └── dependabot.yml               # апдейты digest'ов базовых образов
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
    │   ├── Dockerfile               # вшивает cloud-image и cloud-init seed
    │   ├── fetch-cloudimage.sh      # скачивание cloud-image со сверкой подписи
    │   ├── canonical-cloudimage-key.asc
    │   ├── hooks/10-stage-image.sh  # кладёт qcow2 в /storage на 1-м запуске
    │   └── cloud-init/user-data     # ⇐ редактируй это
    ├── windows/
    │   ├── Dockerfile               # вшивает Win11 ISO + /oem
    │   └── oem/
    │       ├── install.bat          # ⇐ запускается на 1-м логине
    │       └── firstboot.ps1        # ⇐ сюда логику инициализации
    └── macos/
        ├── Dockerfile               # вшивает recovery-образ Apple
        ├── fetch-recovery.sh        # скачивание recovery на сборке
        ├── verify-recovery.py       # сверка с подписанным chunklist'ом Apple
        └── hooks/10-macos.sh
```

Все Dockerfile собираются **из корня репозитория**, потому что используют
общий `shared/`:

```bash
docker build -f images/ubuntu/Dockerfile -t ubuntu-vm .
```

---

## Что попадает в образ на сборке

Образы собираются с нуля из этого репозитория, и всё, что качается на сборке,
сверяется с подписью издателя:

| Что | Проверка |
|---|---|
| Ubuntu cloud image | SHA-256 из `SHA256SUMS` Canonical; сама `SHA256SUMS` — подписью UEC Image Automatic Signing Key (ключ лежит в репозитории) |
| macOS recovery | подписанный chunklist Apple: SHA-256 по каждому куску, подпись — ключом Apple EFI ROM |
| Windows ISO | SHA-256 из `dockur/windows`; по умолчанию несовпадение — предупреждение, см. ниже |

Базовые образы (`qemux/qemu`, `dockurr/windows`, `dockurr/macos`, `debian`,
`golang`) пришпилены по digest, а не по плавающему тегу: апстрим не может
поменять содержимое сборки без коммита сюда. Digest'ы обновляет Dependabot
([`.github/dependabot.yml`](.github/dependabot.yml)), и его PR проходит тот же
CI, что и любой другой.

Для зеркала или своего образа, рядом с которым нет `SHA256SUMS`, хэш задаётся
явно:

```bash
docker build -f images/ubuntu/Dockerfile \
  --build-arg UBUNTU_IMG_URL=https://example.com/my-cloudimg.img \
  --build-arg UBUNTU_IMG_SHA256=<sha256> -t ubuntu-vm .
```

---

## CI / GHCR

Workflow `Build VM images`:

* пушит в GHCR **только с дефолтной ветки**; на любой другой ветке и в PR
  собирает полностью, но ничего не публикует;
* перед сборкой гоняет тесты: `vmguard` (юнит-тесты и тесты с настоящим `passt`
  внутри `qemux/qemu`), верификатор chunklist'а, `shellcheck` по хукам;
* собирает коммит один раз, даже когда push и pull_request приходят вместе.

Ручной запуск с переопределениями:

```bash
gh workflow run "Build VM images" -f targets=macos -f macos_version=14
gh workflow run "Build VM images" -f targets=windows \
  -f win_iso_url='https://software-static.download.prss.microsoft.com/.../...iso' \
  -f win_iso_sha256='<sha256>'
```

Опубликовать образы из не-дефолтной ветки можно только явно:
`-f push_images=true`.

URL и хэш для других редакций Windows — в
[`dockur/windows/src/define.sh`](https://github.com/dockur/windows/blob/master/src/define.sh),
функция `getMido`. Учти: несовпадение SHA256 у Windows ISO по умолчанию только
**предупреждение** в логе, а не ошибка — Microsoft переиздаёт ISO под тем же
URL, и хэши в апстриме отстают. Чтобы сборка падала на несовпадении, собирай с
`--build-arg WIN_ISO_STRICT_VERIFY=Y`.

Permissions: репо → Settings → Actions → General → "Read and write
permissions" для `GITHUB_TOKEN`.

---

## Требования к хосту

- Linux + `/dev/kvm` (KVM включён в BIOS, ядро не блокирует).
- Диски создаются разреженными, так что заявленный `DISK_SIZE` место сразу не
  занимает: Windows после установки — около 20 GB, macOS — несколько десятков.
- Не работает на cloud VPS без nested virt (большинство — без).

Полный список env-переменных:
[qemus/qemu](https://github.com/qemus/qemu),
[dockur/windows](https://github.com/dockur/windows),
[dockur/macos](https://github.com/dockur/macos).
