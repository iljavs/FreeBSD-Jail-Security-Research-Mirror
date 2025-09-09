# FreeBSD Jail Escape — Attack Surface / Entrypoints Map (Assuming root **inside** the jail)

Checklist organized by subsystem with *what to look at* and *why it’s risky*.

---

## Baseline
- **Jail flags (“allow.*”) & params**: Flip kernel interfaces from “namespaced” to “host-relevant.”
- **/dev exposure (devfs rulesets)**: Device nodes + ioctls are the biggest kernel attack surface.
- **Mounts inside the jail**: `nullfs`, `zfs`, `tmpfs`, `devfs`, `fdescfs`, `procfs`, `fusefs`
- **Networking knobs**: VNET, raw sockets, routing sockets, `bpf`/`tun`/`tap`.
- **Legacy IPC & namespaces**: SYSV IPC, POSIX shm/sem/mq, and namespacing quirks.
- **Emulation & misc subsystems**: Linuxulator, FUSE, pf/ipfw/ipf control, crypto, DRM

---

## 1) Jail configuration & “allow.*” gates
**Key toggles (examples; names vary by release/jail.conf):**
- `allow.mount`, `allow.mount.devfs`, `allow.mount.tmpfs`, `allow.mount.nullfs`, `allow.mount.fusefs`, `allow.mount.zfs`
- `allow.raw_sockets`, `allow.socket_af` (non-IPv4/IPv6 families), `allow.tun`, `allow.vmm`
- `allow.sysvipc`, `allow.chflags`, `allow.set_hostname`, `allow.reserved_ports`
- `vnet` (per-jail network stack)
- `enforce_statfs` (what the jail can see of host mounts)
- `devfs_ruleset` id (hardened vs default)

**Why risky:** Unlocks large classes of ioctls/sysctls and mount syscalls with a history of kernel bugs or cross-prison leaks.

**What to collect:**
- `jls -v` (flags, devfs ruleset, vnet, path, hostid)
- `sysctl security.jail` (policy knobs)
- `/etc/jail.conf` for the target jail

---

## 2) Filesystems & mounts (inside the jail)
**Surfaces:**
- **Nullfs** over host paths (even ro): metadata races, permission confusion, path traversal edge cases.
- **devfs**: visible device nodes (see §4).
- **tmpfs/fdescfs/procfs**: `proc/fd` views, pid leakage, kevent/kqueue interactions.
- **ZFS**: delegated datasets or `zfs`/`zpool` binaries; zfs ioctls if `/dev/zfs` exposed.
- **FUSE/fusefs**: userspace FS bridge + kernel module code paths.

**Red flags:**
- Jail can run `mount_*` helpers or has `allow.mount*`.
- Any host path nullfs-mounted that contains device nodes, zfs control sockets, or privileged runtime dirs.

**Quick audit:**
- `mount` (inside jail) for types/targets.
- `sysctl vfs.*` for enabled filesystems; note `fusefs`, `zfs`, `unionfs`, etc.

---

## 3) /dev exposure (devfs rulesets) — **highest value**
**Particularly dangerous device nodes (if present):**
- **Memory/port I/O**: `/dev/kmem`, `/dev/mem`, `/dev/io` → immediate host compromise potential.
- **Net capture/injection**: `/dev/bpf*`, `/dev/tun*`, `/dev/tap*` (+ `allow.raw_sockets`/VNET) → big ioctl parsers.
- **Packet filters & firewalls**: `/dev/pf`, `/dev/ipfw` → powerful control planes, complex ioctls.
- **Crypto & random**: `/dev/crypto` (cryptodev ioctls); `/dev/random` ok read-only.
- **USB & HID**: `/dev/usb/*`, `/dev/uhid*`, `/dev/kbdmux*`.
- **Graphics/DRM**: `/dev/dri/*`, `/dev/drm/*`, `/dev/fb*`.
- **Sound**: `/dev/dsp*`, `/dev/snd/*`.
- **vmm/bhyve**: `/dev/vmm` → hypervisor control from a jail.
- **ZFS control**: `/dev/zfs`.
- **GEOM & disks**: `/dev/da*`, `/dev/ada*`, `/dev/md*`, `/dev/cd*`.
- **Netgraph**: `/dev/ng*` (often via sockets too).

**Quick audit:**
- `devfs rule -ls <ruleset>` (host) and `ls -l /dev` (jail).
- Compare against a minimal baseline: only `null, zero, random, urandom, tty, pts, log, fd` ideally.

---

## 4) Networking (VNET vs shared stack)
**If VNET=off (shared host stack):**
- **Routing socket** (`PF_ROUTE`) and **raw sockets** (`SOCK_RAW`) if `allow.raw_sockets` → rtsock + raw paths.
- **bpf(4)** devices if exposed → attach/inject to host interfaces.
- **Netgraph** (`ng_socket`, `ng_ksocket`, `ng_iface`) → dynamic graph management in kernel.
- **AF families beyond INET/INET6** via `allow.socket_af` (e.g., `AF_KEY`, `AF_NETGRAPH`).

**If VNET=on:**
- Per-jail stack/interfaces but same code paths overall.
- **Interface ioctls** (SIOC*), VLAN/bridge/epair/gre/tun creation if helpers available.
- **Packet filters**: ipfw/ipf/pf.

**Quick audit:**
- `ifconfig -a`, `sockstat -4 -6`, `sockstat -P route,raw`
- Presence of `/dev/bpf*`, `/dev/pf`, `/dev/tun*`
- `sysctl net.graph` (netgraph)

---

## 5) IPC & namespaces
- **SYSV IPC** (`allow.sysvipc`): can be shared across jails depending on version/knobs; id collisions & accounting bugs.
- **POSIX shm/sem/mq**: namespacing/mount nuances (`/dev/shm`, `/var/run`); historic edge cases.
- **kqueue/kevent** on proc/fs/net: multiplies kernel paths exercised.

---

## 6) Process, debugging, and privilege boundaries
- **ptrace(2)**: typically intra-jail but hits shared kernel code; check `security.bsd.see_*`.
- **setuid/chflags** with `allow.chflags`: interactions with nullfs/host mounts can be surprising.
- **capsicum**: misconfig can yield broader capability handles (less common, still map it).

---

## 7) Packet filters & traffic control
- **pf(4)** via `/dev/pf`: rule parsing, tables, pfsync — very large ioctl API.
- **ipfw(4)/dummynet**: setsockopt control planes; high complexity if accessible.
- **ipfilter**

---

## 8) Emulation layers & “big subsystems”
- **Linuxulator** (`linux` ABI): another syscall/setsockopt/ioctl surface.
- **FUSE**: kernel/userspace FS bridge (copyin/copyout heavy).

---

## 9) Time & randomness
- **clock_settime** (usually restricted; if allowed, host-wide impact).
- **/dev/random** usage OK read-only; note entropy device paths.

---

## 10) Resource controls, quotas, accounting
- **rctl(8)**, cpusets, memory limits, credential recycling → refcount/overflow edges.
- **Filesystem quotas** (ZFS/UFS) enforced across jail boundaries; enumerate delegated control.

---

## 11) Host integration “leaks”
- **Host UNIX sockets/files bind-mounted in** (e.g., `/var/run/<daemon>.sock`).
  - Look for privileged daemons (zfs, devd, pf/ipfw helpers, container shims).
- **SSH agent / gpg-agent sockets**: not kernel, but credential pivot path.

---

## 12) Live target quick checklist
Run inside the jail (correlate on host as needed):

1) **Jail facts**
   - `jls -v`
   - `sysctl security.jail`
   - `id; sysctl security.bsd.*`

2) **Mounts & FS**
   - `mount`
   - `sysctl vfs.*`
   - `zfs list` / `zpool list` (if present)

3) **Devices**
   - `devfs rule -ls <ruleset>` (host)
   - `ls -l /dev` (jail)
   - Flag anything beyond minimal baseline (see §3)

4) **Networking**
   - `ifconfig -a`
   - `sockstat -46` and `sockstat -P route,raw`
   - Check for `/dev/bpf*`, `/dev/pf`, `/dev/tun*`, netgraph sockets

5) **IPC**
   - `ipcs -a` (SYSV)
   - Inspect `/dev/shm`, `/var/run`, POSIX queues/semaphores

6) **Capabilities/flags**
   - Try `mount -t <fs>` (expect `EPERM` if not allowed)
   - `sysctl kern.features` / presence of linux compat, fuse, vmm

7) **Host artifacts shared in**
   - `find / -xdev -type s -path '/var/run/*' -o -path '/tmp/*' 2>/dev/null`
   - Look for nullfs binds to sensitive host paths

---

## 13) Prioritized “high-risk” buckets (triage order)
1) **/dev exposure beyond minimal TTY/null/zero/random/log/fd/pty set**
2) **Any mount capability or privileged FS mounted in** (`nullfs`, `devfs`, `zfs`, `fusefs`)
3) **Networking power features**: `allow.raw_sockets`, routing sockets, `bpf/tun/tap`, netgraph, `/dev/pf`
4) **VNET jails with interface creation/teardown control**
5) **SYSV IPC enabled/shared**
6) **Linuxulator/FUSE/vmm present**
7) **Host UNIX/control sockets bind-mounted in**

---

