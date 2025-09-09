# Jailed Root and the Sysctl Attack Surface

FreeBSD’s `sysctl` mechanism is central to exposing kernel state and tunables.  
When considering jails — both *regular* and *VNET-enabled* — it’s important to understand what a **jailed root** can and cannot do with sysctls.

---

## 1. Sysctl Policy in Jails

- **Read filtering:**  
  By default, jails only see a *subset* of the global sysctl MIB tree.  
  Sensitive host-only values (e.g. hardware details, host routing tables) are hidden.

- **Write restrictions:**  
  Jailed root cannot write to arbitrary sysctls.  
  A sysctl must be explicitly marked with one of the following flags to be writable inside a jail:
  - **`CTLFLAG_PRISON`** – allow writes from jails (to a global variable).
  - **`CTLFLAG_VNET`** – the sysctl is bound to per-VNET state (so each jail with its own VNET can modify its own copy).
  - **`CTLFLAG_ANYBODY`** – allow non-root processes as well (rarely safe).

- **Default behavior:**  
  If a sysctl lacks these flags, `sysctl -w` inside a jail returns `Operation not permitted`.

---

## 2. Regular (Non-VNET) Jails

- **View:**  
  They see the filtered sysctl tree. Hardware, devfs, and host routing entries are typically absent.

- **Writes:**  
  They cannot change host-global tunables unless a sysctl was marked `CTLFLAG_PRISON`.

- **Attack surface:**  
  - Accidentally marking a host-global sysctl as `CTLFLAG_PRISON` exposes it to *all jails*.  
  - A jailed root could then alter host behavior (e.g., enabling/disabling a protocol feature).

---

## 3. VNET Jails

- **Per-VNET state:**  
  Many network-related sysctls are defined with `SYSCTL_VNET_*`. These provide each VNET stack with its own copy of the variable.

- **Writes:**  
  Within their own VNET, jailed root can freely toggle those per-VNET sysctls.  
  This is expected: e.g., tuning TCP/IP stack parameters per jail.

- **Global sysctls:**  
  Sysctls not written as `SYSCTL_VNET_*` remain host-global. Unless flagged `CTLFLAG_PRISON`, they cannot be changed by the jail.

- **Attack surface:**  
  - If a global networking sysctl was marked `CTLFLAG_PRISON` instead of `SYSCTL_VNET_*`, jailed root could affect the *host’s* networking stack.  
  - Misflagging here broadens the attack surface significantly.

---

## 4. Misconfiguration Risks

- **Confusion with `allow.sysvipc`:**  
  This only governs System V IPC. It does *not* control sysctl access.

- **No `allow.sysctl`:**  
  There is no generic "allow sysctl" toggle. Control rests entirely on sysctl flags (`CTLFLAG_PRISON`, `CTLFLAG_VNET`, etc.).

- **devfs leaks:**  
  Exposing `/dev/mem`, `/dev/kmem`, or `/dev/bpf` devices in a jail can widen the effective sysctl-like attack surface, since those allow low-level inspection or control outside the intended jail boundary.

---

## 5. Summary

- **Regular jails:** very limited sysctl write capability, unless the kernel marks nodes `CTLFLAG_PRISON`.  
- **VNET jails:** can set their own VNET-specific sysctls, but cannot touch host-global knobs unless misflagged.  
- **Attack surface:** the critical point is which sysctl nodes are flagged incorrectly. A single misflagged global sysctl could let jailed root change host-wide kernel behavior.

---
