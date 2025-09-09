# PF attack surface and entrypoints in a VNET Jail on FreeBSD

## Overview

FreeBSD’s **VNET jails** provide a per-jail network stack, including independent interfaces, routing tables, and firewall rules.  
By default, the packet filter device (`/dev/pf`) is not visible to jails.  
Administrators may selectively expose it to a VNET jail to allow jailed root to manage firewall rules within that jail’s isolated network stack.

While this is a supported configuration, it enlarges the kernel attack surface.  
All operations on `/dev/pf` are handled in the FreeBSD kernel, and any vulnerability in PF’s control plane or datapath is reachable by jailed root.

---

## Attack Surface

When `/dev/pf` is exposed to a jail, the following kernel subsystems are accessible:

- **PF ioctl interface**  
  The primary control channel (`DIOC*` ioctls) used by `pfctl` to load, query, and modify rulesets and state tables.

- **Ruleset parser & loader**  
  Variable-length data structures describing filter, NAT, rdr, and scrub rules are passed from userland and validated in kernel space.

- **Packet processing paths**  
  Traffic inside the VNET jail traverses PF’s filtering, normalization, and state management code. Crafted packets can exercise corner cases.

- **NAT and rdr translation logic**  
  Packet rewriting, address pools, and table lookups are all executed in kernel space.

- **Optional subsystems (if enabled)**  
  - **ALTQ** (queueing and scheduling)  
  - **pfsync** (state synchronization)  
  - **CARP** (redundant IP failover)

---

## IOCTL Interface

The following `ioctl(2)` commands are available through `/dev/pf` (list not exhaustive, based on `sys/net/pfvar.h`):

- **General control**  
  - `DIOCSTART` – Enable PF  
  - `DIOCSTOP` – Disable PF  
  - `DIOCGETSTATUS` – Retrieve current PF status  
  - `DIOCGETTIMEOUT` / `DIOCSETTIMEOUT` – Get/set timeouts  

- **Ruleset management**  
  - `DIOCGETRULES` / `DIOCGETRULE` – Retrieve active rules  
  - `DIOCCHANGERULE` – Add/modify/remove a rule  
  - `DIOCGETRULESETS` / `DIOCGETRULESET` – Query ruleset anchors  

- **State table**  
  - `DIOCGETSTATES` / `DIOCGETSTATE` – Dump current states  
  - `DIOCCLRSTATES` – Flush state table  
  - `DIOCADDSTATE` – Insert a state entry  

- **NAT / rdr**  
  - `DIOCGETNATLOOK` – Query NAT translation  
  - `DIOCCHANGERULE` (with NAT/rdr structs) – Manage NAT/rdr rules  

- **Tables**  
  - `DIOCGETTABLES` / `DIOCGETTABLE` – List tables  
  - `DIOCCHGTABLE` – Modify a table (add/remove addresses)  
  - `DIOCRGETADDRS` / `DIOCRADDADDRS` / `DIOCRDELADDRS` – Table address ops  

- **Anchors**  
  - `DIOCADDANCHOR` / `DIOCGETANCHOR` – Manage anchors  
  - `DIOCGETRULESETS` – Enumerate rulesets  

- **AltQ (if compiled/loaded)**  
  - `DIOCGETQSTATS` – Queue statistics  
  - `DIOCGETALTQS` – List available queues  
  - `DIOCCHANGEALTQ` – Configure ALTQ  

- **Other**  
  - `DIOCSETDEBUG` / `DIOCGETDEBUG` – Control debug level  
  - `DIOCOSFPADD` / `DIOCOSFPGET` – Manage OS fingerprints  
  - `DIOCGETSRCNODES` / `DIOCCLRSRCNODES` – Source node table  

---
