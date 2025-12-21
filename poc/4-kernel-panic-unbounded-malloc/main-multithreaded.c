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
#include <netinet/ip_fw.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#define THREADS 100
#define TABLE_SIZE 0x7FFFFF00

struct ipfw_table_entry {
  struct in_addr addr;
  u_int32_t masklen;
};

struct ipfw_table {
  u_int32_t tbl;
  u_int32_t cnt;
  struct ipfw_table_entry ent[0];
};

// NOTE(m): Requires ipfw kernel module to be loaded in host
/*
sysrc firewall_enable="YES"
sysrc firewall_type="open"
*/

// TODO(m): Clean this code up

void* thread_func(void* arg) {
  int sock;
  struct ipfw_table* tbl;
  socklen_t len;

  sock = socket(AF_INET, SOCK_RAW, 0);
  if (sock < 0) {
    perror("socket");
    return NULL;
  }

  len = TABLE_SIZE;
  tbl = malloc(len);
  if (!tbl) {
    perror("malloc");
    close(sock);
    return NULL;
  }

  tbl->tbl = 1;  // table number to list

  socklen_t l = len;
  if (getsockopt(sock, IPPROTO_IP, IP_FW_TABLE_LIST, tbl, &l) < 0) {
    perror("getsockopt IP_FW_TABLE_LIST");
    free(tbl);
    close(sock);
    return NULL;
  }

  printf("Thread %lu: entries = %u\n", pthread_self(), tbl->cnt);
  for (u_int32_t i = 0; i < tbl->cnt; i++) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &tbl->ent[i].addr, buf, sizeof(buf));
    printf("Thread %lu: %s/%u\n", pthread_self(), buf, tbl->ent[i].masklen);
  }

  free(tbl);
  close(sock);
  return NULL;
}

int main() {
  pthread_t threads[THREADS];

  for (int i = 0; i < THREADS; i++) {
    if (pthread_create(&threads[i], NULL, thread_func, NULL) != 0) {
      perror("pthread_create");
      return 1;
    }
  }

  for (int i = 0; i < THREADS; i++) {
    pthread_join(threads[i], NULL);
  }

  return 0;
}
