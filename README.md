# Pre-baked QEMU VM Docker images

Two opinionated Docker images that wrap a pre-installed VM and run an
initialization script on first boot. Both publish to GHCR via GitHub Actions.

| Image                                  | Base               | OS         | First-boot mechanism            | Image size  |
| -------------------------------------- | ------------------ | ---------- | ------------------------------- | ----------- |
| `ghcr.io/<you>/<repo>-ubuntu-24.04`    | `qemux/qemu`       | Ubuntu 24.04 (cloud image) | cloud-init NoCloud seed   | ~1.0 GB     |
| `ghcr.io/<you>/<repo>-windows-11`      | `dockurr/windows`* | Windows 11 IoT LTSC | OEM `install.bat` at first logon | **~6.3 GB** |

\* `dockurr/windows` itself is built `FROM qemux/qemu` (see its Dockerfile),
so the Windows image transitively satisfies the "on top of qemux/qemu"
requirement. We layer on `dockurr/windows` because it brings the things
you'd otherwise have to re-implement: virtio drivers ISO, mido (the Microsoft
ISO downloader), samba host share, and the unattend answer files.

---

## Repo layout

```
.
├── .github/workflows/build.yml      # CI: matrix build + push to GHCR
└── images/
    ├── ubuntu/
    │   ├── Dockerfile               # Bakes cloud image + cloud-init seed
    │   ├── start.sh                 # Override of qemux/qemu's start hook
    │   └── cloud-init/
    │       ├── user-data            # ⇐ edit this for first-boot logic
    │       └── meta-data
    └── windows/
        ├── Dockerfile               # Bakes the Windows ISO + /oem
        └── oem/
            ├── install.bat          # ⇐ entry point, runs at first logon
            └── firstboot.ps1        # ⇐ where to put real init logic
```

---

## How the Ubuntu image works

The build downloads the Ubuntu 24.04 cloud image (`*.cloudimg.amd64.img`,
~700 MB) — it's already an installed Ubuntu system, not an installer ISO.
We resize the virtual disk to 64 GB and ship it at `/opt/baked/boot.qcow2`.

A NoCloud cloud-init seed is generated from `cloud-init/user-data` +
`meta-data` and shipped at `/start.iso`. Inside the container, qemux/qemu
mounts `/start.iso` automatically as a second CD-ROM (this is its built-in
"RESCUE" media slot — see `qemu-master/src/disk.sh` line 697). cloud-init
sees the `cidata`-volid CD-ROM, applies the config, and runs the embedded
firstboot script.

A custom `/run/start.sh` hook copies `/opt/baked/boot.qcow2` into
`/storage/boot.qcow2` on first run, so writes inside the VM persist across
container restarts via the bound storage volume. qemux/qemu's
`install.sh::findFile` then picks up the qcow2 from `/storage` and boots it
directly without any download.

To customize first-boot behavior, edit `images/ubuntu/cloud-init/user-data`
(the `runcmd:` and `write_files:` sections). Note that cloud-init only runs
**once per disk image** — to re-run, delete the storage volume.

### Run it

```bash
docker run -it --rm --name ubuntu-vm \
  --device=/dev/kvm --device=/dev/net/tun --cap-add NET_ADMIN \
  -p 8006:8006 -p 2222:22 \
  -v ./ubuntu-storage:/storage \
  ghcr.io/<you>/<repo>-ubuntu-24.04:latest
```

Open `http://localhost:8006` for the web console, or
`ssh ubuntu@localhost -p 2222` (default password: `ubuntu`, override via
cloud-init).

---

## How the Windows image works

The build downloads the **Windows 11 IoT Enterprise LTSC** ISO (~4.7 GB,
SHA256-verified) at build time and ships it at `/custom.iso` inside the
image. On first run, `dockurr/windows` finds the pre-baked ISO via its
`findFile()` logic in `install.sh`, skips the mido download path, and
proceeds with the unattended installation. **Zero ISO download at run time.**

Why IoT LTSC by default?
- **4.7 GB** vs **7.2 GB** for the consumer Pro/Home build — final image is
  ~6 GB instead of ~9 GB. Friendlier for slow `docker pull` and the GHA
  10 GB cache quota.
- It's the most stable Win11 SKU — no forced feature updates, no Cortana,
  no Edge bloatware, no Microsoft Store cruft.
- The eval license gives you 90 days; after that the desktop watermarks
  and reboots hourly but the OS itself keeps working. Plenty for lab use.

The `/oem/install.bat` runs at first user logon. dockurr/windows's default
unattend XML for Win11 already contains:

```xml
<CommandLine>cmd /C if exist "C:\OEM\install.bat" start "Install" "cmd /C C:\OEM\install.bat"</CommandLine>
```

so anything dropped into `/oem/` ends up at `C:\OEM\` inside Windows and
`install.bat` fires automatically. We chain to `firstboot.ps1` for any real
work — that's where you put your `winget install`, registry tweaks, etc.

### Run it

```bash
docker run -it --rm --name windows-vm \
  --device=/dev/kvm --device=/dev/net/tun --cap-add NET_ADMIN \
  -p 8006:8006 -p 3389:3389/tcp -p 3389:3389/udp \
  -v ./windows-storage:/storage \
  --stop-timeout 120 \
  ghcr.io/<you>/<repo>-windows-11:latest
```

Open `http://localhost:8006` for installation progress, then RDP to
`localhost:3389` (user `Docker`, password `admin`) once it's ready.
First run takes ~10–15 min for the unattended install to complete; this is
disk-I/O bound, not network — the ISO is already local.

### Switching to the Consumer build

If you actually want vanilla Windows 11 Pro/Home, run the workflow manually
with the consumer URL + hash from
[`windows-master/src/define.sh:712`](https://github.com/dockur/windows/blob/master/src/define.sh):

```bash
gh workflow run "Build VM images" \
  -f win_iso_url='https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26200.6584.250915-1905.25h2_ge_release_svc_refresh_CLIENT_CONSUMER_x64FRE_en-us.iso' \
  -f win_iso_sha256='d141f6030fed50f75e2b03e1eb2e53646c4b21e5386047cb860af5223f102a32'
```

### When the URL goes stale

Microsoft rotates these URLs whenever a new build ships (every few months).
If `sha256sum -c` fails in CI, the `dockur/windows` project has already
updated `src/define.sh` with the new URL+hash by the time you notice.
Either:
1. Update `WIN_ISO_URL` and `WIN_ISO_SHA256` in `images/windows/Dockerfile`, or
2. Run the workflow with `workflow_dispatch` inputs to override.

---

## Requirements at run time

- Linux host with KVM available (`/dev/kvm` exists). `kvm-ok` should pass.
- Cloud / VPS hosts often disable nested virtualization — check before
  deploying there.
- 2 vCPU + 2 GB RAM minimum for Ubuntu, 2 vCPU + 4 GB RAM minimum for Windows.
- ~10 GB free disk for the Windows storage volume (ISO is read once into
  storage, then a 64 GB sparse qcow2 is created for the OS install).

## Customization at run time

Both images respect the standard env vars from `qemux/qemu` /
`dockurr/windows`:

| Var          | Default (Ubuntu / Windows) | Effect                       |
| ------------ | -------------------------- | ---------------------------- |
| `CPU_CORES`  | 2 / 2                      | Number of vCPUs              |
| `RAM_SIZE`   | 2G / 4G                    | RAM size                     |
| `DISK_SIZE`  | 64G / 64G                  | Disk size                    |
| `USERNAME`   | — / Docker                 | Windows guest user           |
| `PASSWORD`   | — / admin                  | Windows guest password       |
| `DHCP`       | N                          | Use macvlan + DHCP for VM IP |

See [github.com/qemus/qemu](https://github.com/qemus/qemu) and
[github.com/dockur/windows](https://github.com/dockur/windows) for the full
list.
