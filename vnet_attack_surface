# FreeBSD VNET Jails – Network Interfaces & Attack Surface (13 vs 14)

A VNET jail has its own network stack. Interfaces/protocols that are **clonable and VNET-aware** can be created inside the jail. From a security perspective, every additional protocol you enable widens the attack surface (kernel code paths, syscalls, device nodes exposed via `devfs`).

---

## ✅ VNET-Safe / Clonable (Usable in Jails)

| Interface / Protocol | FreeBSD 13 | FreeBSD 14 | Attack Surface Notes |
|----------------------|------------|------------|----------------------|
| `lo` (loopback)      | ✅ | ✅ | Minimal risk; local-only traffic. |
| `epair`              | ✅ | ✅ | Common jail link; exposes L2 bridging logic. |
| `bridge`             | ✅ | ✅ | Increases complexity; bridging bugs affect host+jail. |
| `tun` / `tap`        | ✅ | ✅ | Needs `/dev/tun*`/`tap*`; exposes PPP/VPN logic, userland packet injection. |
| `vlan`               | ✅ | ✅ | VLAN tagging/stripping code exposed. |
| `lagg`               | ✅ | ✅ | LACP/failover parsing; multiple NIC interaction. |
| `gif`                | ✅ | ✅ | IP-in-IP tunneling code. |
| `gre`                | ✅ | ✅ | GRE parser/encapsulation exposed. |
| `wg` (WireGuard)     | ✅ (module) | ✅ | Cryptographic tunnel stack; new code, higher scrutiny. |
| `pflog` / `pfsync`   | ✅ | ✅ | PF logging/state sync; parsing of PF state structures. |
| `carp`               | ✅ | ✅ | Redundancy protocol logic; attackable via crafted CARP packets. |
| SLIP (`sl`)          | ✅ | ✅ | Old serial framing code; legacy attack surface. |
| IPsec                | ✅ | ✅ | Cryptographic stack, SPD/SAD mgmt; significant parser complexity. |
| BPF (`/dev/bpf*`)    | ✅ | ✅ | Packet sniff/inject. Must control with `security.jail.vnet.bpf_privileged`. |

---

## ⚠️ Limited / Hardware-Bound

| Interface / Protocol | FreeBSD 13 | FreeBSD 14 | Attack Surface Notes |
|----------------------|------------|------------|----------------------|
| Wi-Fi NICs (`wlan`)  | Host-only unless passed through | Same | Complex 802.11 stack; generally avoid exposing. |
| USB NIC gadgets      | Host-only | Same | Direct hardware passthrough → high risk. |

---

## ❌ Deprecated / Removed / Not VNET-Aware

| Interface / Protocol | FreeBSD 13 | FreeBSD 14 | Attack Surface Notes |
|----------------------|------------|------------|----------------------|
| ATM (`ng_atm`)       | Present but deprecated | **Removed** | Dead code; no drivers; potential latent bugs if enabled in 13. |
| Bluetooth (Netgraph) | Host-only | Host-only | Not namespaced; exposes fragile Netgraph Bluetooth stack. |
| FDDI / Token Ring    | Gone | Gone | Legacy only. |

---

- **Each interface type = more kernel code paths exposed**. Tunnels, VLANs, PPP, and crypto stacks bring additional packet parsers.  
- **Device node exposure (`/dev/bpf*`, `/dev/tun*`)** is a privileged vector; control via `devfs.rules` and sysctls.  
- **Legacy protocols (SLIP, PPP)** have less review today → potentially higher bug density.  
- **Crypto/tunnel protocols (IPsec, WireGuard)** enlarge the attack surface significantly; keep modules unloaded if not needed.  
- **Bridging and aggregation (`bridge`, `lagg`)** extend trust boundaries — crafted L2 frames can reach host code.  
- **Best practice:** expose only the minimal set of interfaces needed by the jailed service.  
