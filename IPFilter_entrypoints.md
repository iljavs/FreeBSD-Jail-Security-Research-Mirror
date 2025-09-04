# IPFilter Local Attack Surface (FreeBSD, jailed root perspective)

## 1. Character devices + ioctls (control plane)

These devices live under **/dev**. Management is via `ioctl(2)`.  
By default, the standard jail `devfs` rules hide them; they’re only reachable if the host exposes them.

- **/dev/ipl** — main filter/log device  
  Ioctls (examples):  
  - `SIOCADDFR`, `SIOCDELFR`, `SIOCIN*` (insert rules)  
  - `SIOCSETFF`, `SIOCGETFF` (flags)  
  - `SIOCIPFFL`, `SIOCIPFFB` (flush)  
  - `SIOCSWAPA` (swap active ruleset)  
  - `SIOCFRENB` (enable/disable)  
  - `SIOCFRSYN` (resync)  
  - `SIOCFRZST` (get+zero stats)  
  - `SIOCZRLST` (zero rule counters)  
  - `SIOCAUTHW`, `SIOCAUTHR`, `SIOCATHST` (packet auth)  

- **/dev/ipnat** — NAT control  
  - `SIOCADNAT`, `SIOCRMNAT`  
  - `SIOCGNATS` (NAT stats)  
  - `SIOCGNATL` (lookup)  

- **/dev/ipstate** — state table access  
  - Used by `ipfstat`  
  - `SIOCIPFFL` flushes state table  

- **/dev/ipauth** — packet authentication queue  
  - Works with `SIOCAUTH*` ioctls  

- **/dev/iplookup** — pools/tables (managed by `ippool(8)`)  

- **/dev/ipl** as `read()` logging stream  
  - Consumed by `ipmon(8)`  

**Jail note:** In non-VNET jails with default devfs rules, these nodes are invisible.  
If exposed, jailed root can issue ioctls and mutate host filter/NAT state.

---

## 2. Sysctls (tuning/flags/timeouts)

Available under **`net.inet.ipf.*`**.  
Examples:  
- `net.inet.ipf.fr_flags`  
- `net.inet.ipf.fr_pass`  
- `net.inet.ipf.fr_active`  
- `net.inet.ipf.fr_tcpidletimeout`  
- `net.inet.ipf.fr_udptimeout`  
- `net.inet.ipf.fr_icmptimeout`

Reads are usually permitted inside jails.  
Writes normally fail unless the host loosens sysctl policy.

---

## 3. Socket-level surface

- No IPFilter-specific `setsockopt()` APIs.  
- Data path only: traffic you send via sockets is filtered/NATed/parsed by IPF.  
- If `security.jail.allow_raw_sockets=1`, you can generate raw IP/ICMP/TCP/UDP to stress parser/state/NAT code.  
- Control remains strictly via `/dev/ip*` + sysctl.

---

## 4. VNET vs. traditional jails

- **Traditional jails:**  
  - No access unless host exposes `/dev/ip*` or allows sysctl writes.  
  - Only attack surface: crafted packets through the data path.  

- **VNET jails:**  
  - Jail has its own IP stack and its own `/dev/ip*` devices.  
  - Ioctls affect the jail’s own filter/NAT instance, not the host’s (unless explicitly shared).

---

## Checklist (jailed root)

- Can I open `/dev/ipl`, `/dev/ipnat`, `/dev/ipstate`, `/dev/ipauth`, `/dev/iplookup`?  
  - Yes → direct ioctl control.  
  - No → only data-path fuzzing.  

- Do `sysctl -a | grep '^net.inet.ipf.'` write attempts succeed?  
  - Yes → can tune live.  
  - No → read-only view.  

- Is `security.jail.allow_raw_sockets=1`?  
  - Yes → can craft packets to stress IPF parsing.  
  - No → limited to ordinary TCP/UDP traffic.

---
