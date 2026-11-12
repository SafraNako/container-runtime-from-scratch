# container-runtime-from-scratch

A very small subset of Docker, written from scratch in pure Python (3.9+, standard library only): it runs a command from a real image
(`alpine`, `debian`, anything on Docker Hub) in its own **PID, mount, UTS, IPC, network and cgroup namespaces**, on an **overlayfs** root made of
the image's layers, with **cgroups v2** limits, Docker's default **capabilities**, a **seccomp** filter, masked `/proc` and `/sys` paths, a
**bridge network** built with hand-written rtnetlink messages, and a **registry client** that pulls images.

It is not a wrapper: there is no `docker`, `runc`, `containerd`, `libseccomp`, `pyroute2` or `ip` in the code. Every system call
(`unshare`, `pivot_root`, `mount`, `prctl`, `setns`, `seccomp`) goes through `ctypes` or `os`; the BPF program of the seccomp filter, the netlink
messages and the layer unpacking are written here. **Real Docker is used by the tests only, as the oracle**: the same image, command and flags
are run by both, and what the process sees from the inside is compared (capabilities, seccomp status, the mount table, `/dev`, `ps`, the
environment, groups, exit codes, limits, OOM kills, stop semantics, terminals, networking, the files of every layer).

```
$ sudo konteyner pull alpine:3.19
0b44b2151d78: pulling 3419815 bytes
alpine:3.19
sha256:83b2b6703a620bf2e001ab57f7adc414d891787b3c59859b1b62909e48dd2242
$ sudo konteyner run --rm alpine:3.19 sh -c 'hostname; ps; grep -E "^(CapEff|CapBnd|Seccomp:)" /proc/self/status'
adbec316e352
PID   USER     TIME  COMMAND
    1 root      0:00 sh -c hostname; ps; grep -E "^(CapEff|CapBnd|Seccomp:)" /proc/self/status
    3 root      0:00 ps
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
Seccomp:	2
$ sudo konteyner run -d --name web -m 64m --cpus 0.5 --pids-limit 50 alpine:3.19 sleep 300
9acaff0201e8739d62f0caae5d87efff43287f617b172f05ba695732310a7f0b
$ sudo konteyner ps
CONTAINER ID   IMAGE         COMMAND       CREATED         STATUS         NAMES
9acaff0201e8   alpine:3.19   "sleep 300"   0 seconds ago   Up 0 seconds   web
$ sudo konteyner exec -it web sh -c 'tty; cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max /sys/fs/cgroup/pids.max'
/dev/pts/0
67108864
50000 100000
50
```

(This is a real session from the test VM, run as `python3 -m kendi_konteyner`; `pip install -e .` gives the `konteyner` command. `CapEff a80425fb` is
Docker's default set of 14 capabilities.)

## It needs Linux

A container is a Linux feature (namespaces, cgroups, overlayfs, `pivot_root`). On a Mac or Windows machine this does not run, and it cannot be
developed there either: it was written and tested in a Linux VM (Ubuntu 24.04, kernel 6.8, cgroups v2, Docker 29.5 next to it as the oracle), and
CI runs it on a GitHub Actions Ubuntu runner. It needs **root**, **cgroups v2** and **overlayfs**; `iptables` is used for one thing, the NAT rule of the
bridge.

## What it can do

| | |
|---|---|
| **Images** | `pull` from any registry (Docker Hub, `ghcr.io`, a local one): token flow, manifest lists, platform choice, every blob checked against its digest, `diff_id`s checked after unpacking; `load` (`docker save` tars, classic and OCI layout), `import` (`docker export` tars), `images`, `rmi`. Layers are unpacked once into `layers/<diff id>` with whiteouts turned into overlayfs whiteouts and opaque directories |
| **Isolation** | six namespaces; `pivot_root` with the old root detached; `/proc`, `/sys` (read only), a `/dev` tmpfs with the six standard devices, `devpts`, `shm`, `mqueue`; `/proc` and `/sys` paths masked or read only as in Docker; hostname, `/etc/hosts`, `/etc/resolv.conf` |
| **Privileges** | the 14 capabilities of Docker's default set (bounding set restricted, so a setuid program cannot get more), `--cap-add/--cap-drop` (including `ALL`), `no_new_privs`, `-u user[:group]` with the supplementary groups Docker gives, `--privileged` |
| **seccomp** | a classic-BPF program assembled by hand and installed with `prctl`: about 50 calls (`mount`, `unshare`, `setns`, `bpf`, `perf_event_open`, `kexec_load`, `init_module`, ...) fail with `EPERM`; `clone` with a namespace flag fails with `EPERM`; `clone3` answers `ENOSYS` so that libc falls back to `clone`; 32-bit and x32 calls are refused |
| **Limits** | `-m` memory (OOM kill, exit code 137, `oom_killed` in the state), `--cpus` (CFS quota), `--pids-limit`; read back from the same cgroup files Docker writes |
| **Networking** | `--network none` (only `lo`), `host`, and the default `bridge`: the bridge `kontbr0` 10.88.0.1/16, a veth pair per container, an address from a lease file, a default route, NAT to the outside. Containers reach each other, the gateway and the Internet; the host reaches containers by address |
| **Processes** | `run` / `create` / `start` / `stop` (SIGTERM, then SIGKILL after the timeout) / `kill` / `rm` / `wait` / `logs` / `ps` / `stats` / `inspect`; `-d`; `--rm`; `--init` (a small PID 1 that forwards signals and reaps zombies); `exec` into a running container (same namespaces, same cgroup, same root, same capabilities and seccomp filter); `-i`, `-t` with a real pseudo terminal made inside the container (`/dev/pts/0`, window size, Ctrl-C, `/dev/console`) |
| **Files** | `-v host:container[:ro]` bind mounts, `--tmpfs`, `--read-only`, `-w`, `-e`, `--entrypoint`, `--hostname` |

## How a container starts

Three processes take part, as in Docker's `containerd-shim` / `runc`:

```
konteyner run ...        the parent: makes the container's directory and cgroup, starts the shim, waits (or attaches)
 └─ shim                 joins the cgroup, unshare(NEWPID), forks the init, leaves the cgroup, waits for the init,
     │                   records the exit code and whether the OOM killer was involved, cleans up
     └─ init (PID 1)     unshare(NEWNS|NEWUTS|NEWIPC|NEWCGROUP|NEWNET), tells the parent "namespaces are ready",
                         waits for the parent to give it a network interface, mounts the overlay, /proc, /dev ..., pivot_root,
                         masks paths, drops capabilities, installs seccomp, and exec()s the command (which stays PID 1)
```

Two details that cost time and are worth knowing:

* After `pivot_root` the host's Python files are gone, so everything the init needs afterwards (`seccomp`, `network`) is imported before.
* A process must not start a thread after `unshare(CLONE_NEWPID)`; the log copier of a detached container is a second forked process, made
  before the PID namespace, not a thread.

The terminal is made **inside** the container (`/dev/ptmx` of the container's own `devpts`, mounted with `newinstance`), and the master end is sent to
the parent with `SCM_RIGHTS`. A pty made on the host would have no name in the container (`tty` would print "not a tty"); this is what runc does,
and it was a real bug here until the Docker comparison caught it.

## How it is checked

`pytest` as root on Linux with Docker installed (without them the tests that need them are skipped, and the pure ones still run). In the VM (Ubuntu 24.04, kernel 6.8, Docker 29.5.2, Python 3.12) the whole suite is **178 tests: 178 passed, none skipped, 3 min 33 s**. The pure tests (sizes, parsers, the BPF program, netlink encoding) run anywhere.

| | what is compared | against |
|---|---|---|
| `test_run` | `CapEff/CapPrm/CapBnd`, `Seccomp`, the mount table, `/dev`, `/proc` and `/sys` contents, `ps`, `env`, `id`, groups, hostname, exit codes (126, 127), `-u`, `-e`, `-w`, `--read-only`, `--tmpfs`, `-v` | `docker run`, same image and flags |
| `test_limits` | `memory.max`, `cpu.max`, `pids.max`; `tail /dev/zero` under `-m 32m` is OOM-killed with 137 and flagged `oom_killed`; exactly 7 `sleep`s fit under `--pids-limit 8` (the shell is the eighth); a fork bomb stays inside its limit; two busy loops under `--cpus 0.5` get about 1.5 s of CPU in 3 s, within 0.7 s of what Docker gives | Docker's results and the cgroup files |
| `test_lifecycle` | `stop` on a PID 1 that ignores SIGTERM (137 after the timeout), with a trap (quick), with `--init` (143); `kill`, `wait`, `rm -f`, `--rm`, restart, names, leftovers | Docker's exit codes and timing |
| `test_exec` | the same namespaces and cgroup as PID 1, capabilities, seccomp, `-u/-w/-e`, exit codes 126/127 | `docker exec` |
| `test_network` | `none` / `host` / `bridge`: addresses and routes read back with the real `ip`; ping the gateway, container to container, host to container, NAT to 1.1.1.1 | `ip`, `docker run --network` |
| `test_layers` | the file tree of an unpacked image: modes, owners, mtimes, symlinks, hard links, whiteouts, opaque directories, a path that tries to leave the layer | `docker export`, the kernel's overlayfs |
| `test_image`, `test_registry` | image ids and `diff_id`s; `pull` from Docker Hub gives the image Docker has; a local fake registry for the token flow, a 404, a corrupted blob (refused), a manifest list without this platform | `docker save`, Docker Hub |
| `test_security` | `mount`, `unshare`, `mknod` + open of a block device, `/proc/kcore`, `/proc/sysrq-trigger`, writing to `/sys`, killing a host process, reaching the host's loopback, `no-new-privileges` with a non-root user | Docker's answers to the same attempts |
| `test_tty` | `tty`, `$TERM`, window size, Ctrl-C, echo and line editing, `exec -it`, standard input without a terminal | `docker run -it` |
| `test_cgroups`, `test_netlink` | the cgroup API against the kernel's files (and a Docker container's cgroup for the same flags); rtnetlink against `ip -j` output, errors against `errno` | the kernel, `ip` |
| `test_seccomp` | every system call number in the tables against **libseccomp**, for x86_64 and aarch64; the BPF program on paper (a small interpreter) against the **kernel** running it: each denied call really fails with `EPERM`, `clone3` with `ENOSYS`, `fork` and threads still work | libseccomp, the kernel |

## Known differences from Docker

Honest list; everything here was seen, not guessed.

* **The seccomp profile is a deny list** (about 50 calls); Docker's is an allow list of about 350, produced by libseccomp. A call that Docker's
  profile does not allow but that is not in this list is allowed here. The difference is a few calls on a kernel that has them; with the
  default capability set most of the denied calls would fail anyway, and the filter is a second wall.
* **No device cgroup.** Docker stops `mknod` + `open` of a block device with a BPF program on the device cgroup. Here the root overlay and the `/dev`
  tmpfs are mounted `nodev`, so a node that is made cannot be opened (tested: it is made, and reading it fails).
* **The six standard devices are bind mounts of the host's**, so `/proc/self/mountinfo` has six more lines than Docker's (they show up as
  `devtmpfs`), and `/` and `/dev` are `nodev`.
* No user namespaces (the container's root is the host's root with fewer capabilities), no AppArmor or SELinux profile.
* **Image id** is the sha256 of the image config, which is what `docker save` writes as `Config`; `docker inspect .Id` shows the digest of the index
  with the containerd image store of recent versions. The tests compare against the first.
* `pull` handles public images only (anonymous tokens): no login, no `docker.io` credentials, no zstd-compressed layers, one platform (this machine's).
* No `build`, no `-p` (port publishing: reach a container by its address instead), no volumes or networks as objects, IPv4 only, one bridge.
* Needs **root** and **cgroups v2**; the memory limit also switches swap off for the container (`memory.swap.max 0`).
* The supplementary groups of `exec -u user` follow Docker 29 (a group that lists the user is there once). Docker 28.0 lists the primary group twice
  (`groups=1,2,2,4`); the test compares the groups as a set, so that it passes against both.
* Without `--pids-limit` the container has no process limit (`pids.max` is `max`). Docker on a host whose cgroup driver is systemd shows the
  `TasksMax` that systemd gives every scope instead (17436 on the GitHub runner), and the test accepts both.
* A container is not a security boundary here that anyone should rely on. This is a learning project that was compared with Docker on what it could
  compare, not a reviewed sandbox.

## Benchmark

`sudo python3 benchmarks/bench.py` times `run --rm IMAGE true` and measures what stays outside the container while it runs, against Docker.
Docker has a daemon that is already running; this is a Python process that starts, imports and forks three times.

```
python 3.12.3, kernel 6.8.0-117-generic, 20 runs each (milliseconds)

| run --rm IMAGE true                |   median |     best |      p90 |
|------------------------------------|----------|----------|----------|
| this runtime, --network none       |      368 |      285 |      653 |
| docker,       --network none       |      693 |      551 |     1449 |
| this runtime, --network bridge     |      370 |      318 |      498 |
| docker,       --network bridge     |      779 |      545 |     1313 |

what stays outside while ten containers run (`sleep 300`, kilobytes of resident memory)

|                                    |  per box |
|------------------------------------|----------|
| this runtime (shim + log process)  |    34791 |
| docker (containerd-shim only)      |    10959 |
```

Measured in the same Linux VM as the tests (20 runs, one warm-up not counted). Read it with care: it is one VM, and Docker's time includes the
round trip to its daemon and containerd. This runtime starts faster in this setup (about 370 ms against about 700 ms), but it is not lighter: the
Python processes that stay behind a container (the shim and, for a detached one, the log process) take about 35 MB together, against about 11 MB
for Docker's `containerd-shim` (which is not counted with the daemons that Docker shares among all containers).

## Layout

```
src/kendi_konteyner/
  runtime.py   the three processes, the root file system, privileges, terminals, exec, stop
  linux.py     ctypes: unshare, setns, mount, pivot_root, prctl, capabilities
  seccomp.py   the BPF program and its installation (and a small BPF interpreter for the tests)
  cgroups.py   cgroups v2
  netlink.py   rtnetlink: links, veth, bridge, addresses, routes
  network.py   none / host / bridge, the address leases, NAT
  registry.py  Docker Registry HTTP API v2 client
  image.py     pull, load, import, image ids
  layers.py    unpacking a layer with overlayfs whiteouts, safe against hostile tars
  store.py spec.py cli.py errors.py
tests/         the oracle tests (see above)
benchmarks/    bench.py
```

## Running the tests

```
sudo python3 -m pip install pytest        # or: pip install -e '.[dev]'
sudo python3 -m pytest -v                 # needs Docker for the comparisons; it pulls alpine:3.19 if it is missing
```

On a Mac, use a Linux VM (Colima, Lima, Multipass, a cloud machine): the code is edited on the Mac and run in the VM.

## License

MIT
