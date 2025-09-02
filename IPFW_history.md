# A History of IPFW

## 1. The Beginnings (Early 1990s)

**1993–1994:**
- IPFW (IP Firewall) was created by **Daniel Boulet** of the Communications Research Centre (CRC), Ottawa, and merged into **FreeBSD 2.0**.  
- One of the **first packet filtering firewalls** integrated directly into a Unix-like kernel.  
- Initially very simple: rules could **accept, deny, or count** packets based on basic IP header fields.  
- Integrated with the BSD networking stack’s `ip_input()` and `ip_output()` functions.  

---

## 2. Expansion & Early Features (Mid to Late 1990s)

**1996:**  
- **Luigi Rizzo** (University of Pisa) enhanced IPFW with:  
  - **dummynet** — a traffic shaper and network emulator.  
    - Allowed simulation of bandwidth limitations, latency, and packet loss.  
    - Widely adopted in research and academia for testing protocols under adverse conditions.  
  - **Stateful rules** (basic connection tracking).  

- During this period, IPFW became a **core FreeBSD firewall**, predating Linux’s `ipchains` and later `iptables`.  

---

## 3. The Shift to IPFW2 (2001–2002)

By FreeBSD 4.x, IPFW had grown unwieldy:  
- Rule representation was rigid and not easily extensible.  
- 32-bit counters limited statistics.  
- No clean way to extend rule types without major rewrites.  

**2002:**  
- Luigi Rizzo led a **redesign**, resulting in **IPFW2**, which shipped in **FreeBSD 5.0 (January 2003)**.  
- Major improvements:  
  - Rule storage switched to a more flexible internal representation.  
  - Support for **64-bit counters**.  
  - Expanded matching capabilities (MAC addresses, IPv6 support, more protocols).  
  - Modularized dummynet integration.  
- **Backward compatibility** with old ipfw syntax was preserved.  

---

## 4. Competition with PF and IPFilter (2000s)

- **2001:** OpenBSD’s **PF** appeared, with simpler syntax and modern NAT.  
- **IPFilter** (originally for SunOS/Solaris, later NetBSD/FreeBSD) was also present.  
- FreeBSD began to **ship all three** (ipfw, pf, ipfilter) so administrators could choose.  

Despite competition, IPFW retained a niche:  
- Strong integration with **dummynet** (research & testing).  
- Favorable for **embedded** and **performance-sensitive** applications.  
- NAT support (via `ipfw nat` or later integrated `libalias`).  

---

## 5. Modern Enhancements (2010s–Present)

IPFW2 has been continually maintained in FreeBSD:  
- Improved **IPv6 support**.  
- **SMP scalability** fixes.  
- Better **NAT functionality**.  
- **Table-based lookups** (efficient handling of large rule sets).  

**Widely used in:**  
- ISPs for **traffic shaping**.  
- Universities and research labs for **dummynet-based network experiments**.  
- Some commercial firewall appliances (though PF and Linux iptables/nftables dominate this market).  

---

## 📌 Key Innovations

- **First integrated firewall** in a BSD Unix kernel (1994).  
- **Dummynet (1996):** one of the most powerful and flexible traffic shaping/emulation systems.  
- **IPFW2 (2002):** modular, extensible redesign.  
- Long-term survival as a **research tool**, even as PF became the de facto firewall for many BSDs.  

---

## ⚖️ Current Status

In FreeBSD today:  
- **IPFW2 is still part of the base system.**  
- **PF** is more commonly recommended for general-purpose firewalls.  

**IPFW’s main strengths:**  
- Dummynet for **simulation**.  
- Complex **policy routing** and **traffic accounting**.  
- Long-term **compatibility and stability**.  

---

## 👉 In Short

- Born in **1994 (FreeBSD 2.0)**.  
- Reinvented in **2002 (IPFW2, FreeBSD 5.0)**.  
- Still maintained today, especially valuable in **research** and **traffic shaping**, though PF has eclipsed it in popularity as a firewall.  
