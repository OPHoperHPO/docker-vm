# Pre-baked VM Docker images

Два Docker-образа с уже встроенной ОС и init-скриптами. Под капотом —
QEMU/KVM (`qemux/qemu` и `dockurr/windows`).

| Образ | ОС | Размер |
|---|---|---|
| `ghcr.io/<you>/<repo>-ubuntu-24.04` | Ubuntu 24.04 cloud image | ~1 GB |
| `ghcr.io/<you>/<repo>-windows-11` | Windows 11 IoT LTSC | ~6.3 GB |

Никаких скачиваний при первом старте — ISO/qcow2 уже внутри образа.

---

## Структура

```
.
├── .github/workflows/build.yml      # CI: matrix-сборка → push в GHCR
└── images/
    ├── ubuntu/
    │   ├── Dockerfile               # Бакает cloud-image и cloud-init seed
    │   ├── start.sh                 # Хук: копирует qcow2 в /storage на 1-м запуске
    │   └── cloud-init/
    │       ├── user-data            # ⇐ редактируй это
    │       └── meta-data
    └── windows/
        ├── Dockerfile               # Бакает Win11 ISO + /oem
        └── oem/
            ├── install.bat          # ⇐ запускается на 1-м логине
            └── firstboot.ps1        # ⇐ сюда логику инициализации
```

---

## Запуск

### docker-compose (рекомендуется)

Минимум привилегий, доступ из других контейнеров через docker network:

```yaml
networks:
  vm-net:
    driver: bridge

services:
  ubuntu:
    image: ghcr.io/<you>/<repo>-ubuntu-24.04:latest
    networks: [vm-net]
    devices:
      - /dev/kvm                    # единственное обязательное устройство
    environment:
      NETWORK: passt                # user-mode networking (без NET_ADMIN)
      PASST_OPTS: "-t all -u all"   # форвард всех TCP+UDP портов VM
    ports:
      - "8006:8006"                 # web-консоль qemu (только для тебя)
    volumes:
      - ./ubuntu-storage:/storage

  windows:
    image: ghcr.io/<you>/<repo>-windows-11:latest
    networks: [vm-net]
    devices:
      - /dev/kvm
    environment:
      NETWORK: passt
      PASST_OPTS: "-t all -u all"
    ports:
      - "8007:8006"                 # web-консоль (порт изменён, чтобы не конфликтовал)
    volumes:
      - ./windows-storage:/storage
    stop_grace_period: 2m

  # пример клиента — ходит в VM просто по имени сервиса:
  app:
    image: alpine
    networks: [vm-net]
    command: sh -c "apk add --no-cache curl && curl http://ubuntu:8080"
```

После `docker compose up`:
- Web-консоль Ubuntu: <http://localhost:8006>
- Web-консоль Windows: <http://localhost:8007>
- Из других контейнеров на `vm-net`: `ubuntu:<port>`, `windows:3389` (RDP), `windows:445` (SMB), и т.д.

### docker run

```bash
docker run -d --name ubuntu-vm \
  --device=/dev/kvm \
  -e NETWORK=passt -e PASST_OPTS="-t all -u all" \
  -p 8006:8006 \
  -v ./ubuntu-storage:/storage \
  ghcr.io/<you>/<repo>-ubuntu-24.04:latest
```

Первый запуск Ubuntu — ~30 секунд до cloud-init готовности.
Первый запуск Windows — ~10–15 минут unattended-инсталляции (диск, не сеть).
SSH/RDP credentials по умолчанию: `ubuntu/ubuntu`, `Docker/admin`.

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

---

## Режимы сети (overview)

В compose-примере выше — `passt`. Если нужно что-то другое:

| `NETWORK=` | Привилегии | Когда использовать |
|---|---|---|
| `passt` (compose выше) | `/dev/kvm` | По умолчанию для всего |
| `slirp` | `/dev/kvm` | Если passt падает (старое ядро) |
| `tap` (default в `qemux/qemu`) | `+ NET_ADMIN, /dev/net/tun` | Нужна максимальная пропускная способность |
| `DHCP=Y` (macvlan) | `+ NET_ADMIN, vhost-net, cgroup rules` | VM нужен свой IP в LAN роутера |

Для passt порты можно либо `PASST_OPTS="-t all -u all"` (всё), либо
`USER_PORTS="22,80,443"` (явный список).

---

## CI / GHCR

Workflow `Build VM images` собирает оба образа на push в `main` и пушит в
GHCR. Permissions: репо → Settings → Actions → General → "Read and write
permissions" для `GITHUB_TOKEN`.

Ручной запуск с переопределением Windows ISO:

```bash
gh workflow run "Build VM images" \
  -f win_iso_url='https://software-static.download.prss.microsoft.com/.../...iso' \
  -f win_iso_sha256='<sha256>'
```

URL+hash для других редакций Windows смотри в
[`dockur/windows/src/define.sh`](https://github.com/dockur/windows/blob/master/src/define.sh)
(функция `getMido`). Когда дефолтный URL стухнет (Microsoft меняет билды раз
в 3–6 месяцев), `sha256sum -c` упадёт в CI — обнови
`WIN_ISO_URL`/`WIN_ISO_SHA256` в `images/windows/Dockerfile` оттуда же.

---

## Требования к хосту

- Linux + `/dev/kvm` (KVM включён в BIOS, ядро не блокирует).
- ~10 GB свободного диска под Windows storage volume (sparse qcow2 64 GB).
- Не работает на cloud VPS без nested virt (большинство — без).

Полный список env-переменных:
[qemus/qemu](https://github.com/qemus/qemu),
[dockur/windows](https://github.com/dockur/windows).
