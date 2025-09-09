`ipfw(4)` is controlled via **`setsockopt(2)` / `getsockopt(2)` calls on a raw socket**  
(`socket(AF_INET, SOCK_RAW, IPPROTO_RAW)`) or through the `ipfw(8)` tool.  
The kernel interface lives in `netinet/ip_fw.h`.

---

## Key sockopt families

### Rule and table management
- `IP_FW_ADD` — add a firewall rule
- `IP_FW_DEL` — delete a rule (by number or all)
- `IP_FW_FLUSH` — flush all rules
- `IP_FW_GET` — get ruleset (dump)
- `IP_FW_ZERO` — zero counters for rules
- `IP_FW_RESETLOG` — reset logging counters

### NAT and sets
- `IP_FW_NAT_CFG` — configure NAT instance
- `IP_FW_NAT_DEL` — delete NAT instance
- `IP_FW_NAT_GETCFG` — retrieve NAT configuration
- `IP_FW_NAT_GET_LOG` — get NAT logs

### Tables
- `IP_FW_TABLE_ADD` — add entry to table
- `IP_FW_TABLE_DEL` — remove entry from table
- `IP_FW_TABLE_FLUSH` — flush table
- `IP_FW_TABLE_GETSIZE` — query table size
- `IP_FW_TABLE_LIST` — list table entries

### Dummynet / traffic shaping
- `IP_DUMMYNET_CONFIGURE` — configure pipe/queue
- `IP_DUMMYNET_DEL` — delete pipe/queue
- `IP_DUMMYNET_FLUSH` — flush all pipes/queues
- `IP_DUMMYNET_GET` — get dummynet configuration

---

## Example request structure

Most sockopts use `struct ip_fw_rule` or related types:

```c
struct ip_fw_rule {
    uint16_t rulenum;   /* Rule number */
    uint8_t  set;       /* Rule set */
    uint8_t  flags;     /* Misc flags */
    uint32_t cmd_len;   /* Length of commands */
    uint32_t act_ofs;   /* Offset of action */
    uint32_t next_rule; /* Next rule in chain */
    uint32_t cmd[1];    /* Array of opcodes (actions/matchers) */
};
```

- Rules are arrays of **opcodes** (`struct ip_fw_insn`).
- Each opcode encodes a match condition or an action (`O_ACCEPT`, `O_DENY`, `O_COUNT`, `O_NAT`, etc, there's many of them, several dozens (> 70)).
- `ipfw(8)` constructs these structs, then calls `setsockopt(2)` with them.

---

## Usage pattern (userspace)

TODO

---

## Why it matters (attack surface)

- sockopt handlers live in `sys/netpfil/ipfw/ip_fw_sockopt.c`.
- They parse user-supplied structs (`ip_fw_rule`, `ip_fw_insn`, table entries).
- Common bug classes:
  - Malformed opcode arrays (`cmd_len`, `act_ofs` inconsistencies)
  - Bounds-checking errors in tables
  - Reference leaks in NAT/dummynet config
  - Copyin/copyout size mismatches

**In short:** ipfw’s sockopt API is a large, complex binary parser in the kernel.
