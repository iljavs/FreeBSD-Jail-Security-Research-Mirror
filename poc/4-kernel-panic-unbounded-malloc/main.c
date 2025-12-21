/*
 * ---------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Ilja van Sprundel and Michael Smith wrote this file. As long as you retain
 * this notice you can do whatever you want with this stuff. If we meet some
 * day, and you think this stuff is worth it, you can buy us a beer in return
 * ---------------------------------------------------------------------------
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#define IPFW_TABLES_MAX 128

struct ipfw_table_entry {
  struct in_addr addr; /* IPv4 address */
  u_int32_t masklen;   /* masklen for subnet */
};

struct ipfw_table {
  u_int32_t tbl;                  /* table number */
  u_int32_t cnt;                  /* # of entries */
  struct ipfw_table_entry ent[0]; /* variable size array */
};

#include <netinet/ip_fw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

// NOTE(m): Requires ipfw kernel module to be loaded in host
/*
sysrc firewall_enable="YES"
sysrc firewall_type="open"
*/

int main() {
  int sock;
  struct ipfw_table* tbl;
  socklen_t l;
  int i;

  sock = socket(AF_INET, SOCK_RAW, 0);
  if (sock < 0) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  // allocate space for up to 128 entries
  // l = sizeof(struct ipfw_table) + 128 * sizeof(struct ipfw_table_entry);

  // TODO(m): Figure out why l and huge are related? Cfc. "Bad address" error.
  l = 0x7FFFFF00;
  tbl = malloc(l);
  if (!tbl) {
    perror("malloc");
    close(sock);
    return 1;
  }

  // memset(tbl, 0, l);

  tbl->tbl = 1;  // table number you want to list

  socklen_t huge = 0x7FFFFF00;

  int error;
  if ((error = getsockopt(sock, IPPROTO_IP, IP_FW_TABLE_LIST, tbl, &huge)) < 0) {
    printf("%d\n", error);
    printf("%d\n", errno);
    perror("setsockopt IP_FW_TABLE_LIST");
    close(sock);
    exit(EXIT_FAILURE);
  }

  // We don't really care about the below because we hope to never get there
  printf("Entries in table %u:\n", tbl->tbl);
  for (i = 0; i < tbl->cnt; i++) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &tbl->ent[i].addr, buf, sizeof(buf));
    printf("  %s/%u\n", buf, tbl->ent[i].masklen);
  }

  free(tbl);
  close(sock);
  return 0;
}
