# Tracing IPFW, pf, and IPFilter control paths with DTrace on FreeBSD 14.3

This document shows two layers of tracing:

1) **Syscall-level** taps to see `setsockopt()` (IPFW) and `ioctl()` (pf, IPFilter).
2) **Component-level** taps using **FBT/kinst** to hook the actual kernel handlers (pf’s `pf_ioctl()`, IPFW’s sockopt handlers, IPFilter’s ioctl handler).

---

## 0) Prep: load DTrace + (optional) unprivileged toggle

```sh
# as root
kldload dtraceall

# Optional: allow non-root to run some DTrace scripts
sysctl security.bsd.unprivileged_dtrace=1
```

> Tip: You can run DTrace with the C preprocessor. `-C -I /usr/include` lets you `#include` kernel headers so you can use symbolic constants (e.g., `IPPROTO_IP`, `IP_FW_ADD`, `DIOCADDRULE`) in your predicates/printfs.

---

## 1) Syscall tracing: IPFW via setsockopt()

`ipfw(8)` controls the firewall using `setsockopt()` with `IPPROTO_IP` and `IP_FW_*` option names.

### Minimal numeric dump
```sh
dtrace -n '
syscall::setsockopt:entry
/ args[1] == IPPROTO_IP /
{
    printf("%Y pid=%d exe=%s name=%d size=%d",
           walltimestamp, pid, execname, (int)args[2], (int)args[4]);
}'
```

### Friendly names using headers
```sh
dtrace -C -I /usr/include -n '
#include <netinet/in.h>
#include <netinet/ip_fw.h>

inline string ipfw_optname(int n)
{
    switch (n) {
        case IP_FW_ADD:   return "IP_FW_ADD";
        case IP_FW_DEL:   return "IP_FW_DEL";
        case IP_FW_FLUSH: return "IP_FW_FLUSH";
        case IP_FW_ZERO:  return "IP_FW_ZERO";
        case IP_FW_GET:   return "IP_FW_GET";
        default:          return "IP_FW_*";
    }
}

syscall::setsockopt:entry
/ args[1] == IPPROTO_IP /
{
    printf("%Y pid=%d exe=%s %-12s sock=%d size=%d",
           walltimestamp, pid, execname, ipfw_optname((int)args[2]),
           (int)args[0], (int)args[4]);
}'
```

---

## 2) Syscall tracing: pf via ioctl() to /dev/pf

Userland (`pfctl` etc.) manipulates pf by `ioctl()` commands (`DIOC*`) on `/dev/pf`.

```sh
dtrace -C -I /usr/include -n '
#include <sys/ioccom.h>
#include <net/pfvar.h>

inline string pf_cmdname(unsigned long c)
{
    switch (c) {
        case DIOCSTART:       return "DIOCSTART";
        case DIOCSTOP:        return "DIOCSTOP";
        case DIOCADDRULE:     return "DIOCADDRULE";
        case DIOCGETRULES:    return "DIOCGETRULES";
        case DIOCGETSTATUS:   return "DIOCGETSTATUS";
        case DIOCRCLR:        return "DIOCRCLR";
        default:              return "DIOC*";
    }
}

syscall::ioctl:entry
/ execname == "pfctl" || execname == "sshguard" || execname == "unbound-anchor" /
{
    printf("%Y pid=%d exe=%s cmd=%s(0x%lx) fd=%d",
           walltimestamp, pid, execname, pf_cmdname(args[1]),
           args[1], (int)args[0]);
}'
```

> To catch *any* process, drop the `execname` filter.

---

## 3) Syscall tracing: IPFilter via ioctl() to /dev/ipl

IPFilter (`ipf`, `ipnat`, `ipfstat`) uses `SIOC*` ioctls on `/dev/ipl` et al.

```sh
dtrace -C -I /usr/include -n '
#include <sys/ioccom.h>
#include <netinet/ip_fil.h>

inline string ipf_cmdname(unsigned long c)
{
    switch (c) {
        case SIOCADDFR:   return "SIOCADDFR";
        case SIOCDELFR:   return "SIOCDELFR";
        case SIOCIPFFL:   return "SIOCIPFFL";
        case SIOCSIFFLAGS:return "SIOCSIFFLAGS";
        default:          return "SIOC*";
    }
}

syscall::ioctl:entry
/ execname == "ipf" || execname == "ipnat" || execname == "ipfstat" /
{
    printf("%Y pid=%d exe=%s cmd=%s(0x%lx) fd=%d",
           walltimestamp, pid, execname, ipf_cmdname(args[1]),
           args[1], (int)args[0]);
}'
```

---

## 4) Handy syscall-level one-liners

Top callers to selected pf commands:
```sh
dtrace -C -I /usr/include -n '
#include <net/pfvar.h>
syscall::ioctl:entry / args[1] == DIOCADDRULE || args[1] == DIOCGETSTATUS /
{ @[execname] = count(); }'
```

Latency of a pf rule update:
```sh
dtrace -C -I /usr/include -n '
#include <net/pfvar.h>
syscall::ioctl:entry / args[1] == DIOCADDRULE / { self->ts = timestamp; }
syscall::ioctl:return / self->ts / {
    @usec = quantize((timestamp - self->ts) / 1000);
    self->ts = 0;
}'
```

Only watch your test process (replace `$PID`):
```sh
dtrace -n 'syscall::setsockopt:entry / pid == $target / { trace(args[2]); }' -p $PID
```

---

## 5) Component-level tracing with FBT (and kinst)

You can hook the **actual kernel handlers** that implement these control paths using **FBT** (function-boundary tracing). If something is too tiny/inlined, use **kinst** to probe by instruction address.

- **IPFW**: control path via sockopt handlers in `sys/netpfil/ipfw/ip_fw_sockopt.c`.
- **pf**: `/dev/pf` ioctls handled by `pf_ioctl()` in `sys/netpfil/pf/pf_ioctl.c`.
- **IPFilter**: `/dev/ipl` ioctl handler lives in the `ipl` module (symbol name varies—list probes).

### 5.1 Discover symbols to hook
```sh
# Which modules are loaded?
kldstat | egrep 'pf|ipfw|ipl'

# pf entry points (look for pf_ioctl)
dtrace -l -m pf | egrep -i 'ioctl|rule|anchor'

# ipfw control helpers (look for *sockopt* or *ctl*)
dtrace -l -m ipfw | egrep -i 'sockopt|ctl'

# ipfilter ioctl handlers (module usually named "ipl")
dtrace -l -m ipl | egrep -i 'ioctl'
```

### 5.2 pf: trace the kernel ioctl handler
```sh
dtrace -n '
fbt:pf:pf_ioctl:entry
{
  this->cmd = (unsigned long)arg1;
  printf("%Y pid=%d exe=%s pf_ioctl(cmd=0x%lx) fd=%d",
         walltimestamp, pid, execname, this->cmd, (int)arg0);
}

fbt:pf:pf_ioctl:return
/ arg1 != 0 /
{
  printf("%Y pid=%d exe=%s pf_ioctl -> errno=%d",
         walltimestamp, pid, execname, (int)arg1);
}'
```

### 5.3 IPFW: trace the in-kernel setsockopt control path
```sh
dtrace -n '
fbt:ipfw::*sockopt*::entry,
fbt:ipfw::*ctl*::entry
{
  printf("%Y pid=%d exe=%s %s()", walltimestamp, pid, execname, probefunc);
}

fbt:ipfw::*sockopt*::return,
fbt:ipfw::*ctl*::return
{
  printf("%Y pid=%d exe=%s %s -> %d",
         walltimestamp, pid, execname, probefunc, (int)arg1);
}'
```

### 5.4 IPFilter: trace the kernel ioctl handler
```sh
# After you identify the symbol (e.g., iplioctl, frioctl), hook it:
dtrace -n '
fbt:ipl:iplioctl:entry
{
  printf("%Y pid=%d exe=%s iplioctl(cmd=0x%lx) fd=%d",
         walltimestamp, pid, execname, (unsigned long)arg1, (int)arg0);
}
fbt:ipl:iplioctl:return
{
  printf("%Y pid=%d exe=%s iplioctl -> %d",
         walltimestamp, pid, execname, (int)arg1);
}'
```

### 5.5 If a function is optimized/inlined: use kinst
```sh
# Hook the first instruction of pf_ioctl() as a fallback
dtrace -n 'kinst:pf:pf_ioctl:1 { printf("pf_ioctl entered by %s", execname); }'
```

---

## 6) Why this works (quick recap)

- DTrace’s **syscall** provider gives you process-facing control points (`setsockopt`, `ioctl`).
- **FBT** drills into **kernel function** entry/return—ideal for observing the *component* handlers.
- **kinst** can probe any instruction when FBT cannot place a probe (e.g., tiny/inlined bodies).
- IPFW control is via `setsockopt(IPPROTO_IP, IP_FW_*)`; pf via `/dev/pf` ioctls (`DIOC*`); IPFilter via `/dev/ipl` ioctls (`SIOC*`).

---

## 7) Further reading

- FreeBSD Handbook: [DTrace chapter](https://docs.freebsd.org/en/books/handbook/dtrace/)  
- Brendan Gregg’s site: [DTrace tools & tutorials](http://www.brendangregg.com/dtrace.html)  
- Books:
  - *DTrace: Dynamic Tracing in Oracle Solaris, Mac OS X, and FreeBSD* (Gregg, Mauro, Snowden)  
  - *Systems Performance: Enterprise and the Cloud* (Brendan Gregg) — broader performance analysis, with DTrace examples  

---

