#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_fw.h>
#include <netinet/ip_dummynet.h>

/*
qemu-system-x86_64 \
  -m 128M \
  -cpu Haswell,-avx \
  -smp 2 \
  -machine q35,accel=tcg \
  -drive file=FreeBSD-14.3-RELEASE-amd64.qcow2,format=qcow2 \
  -device e1000,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -nographic \
  -serial mon:stdio \
  -vga none \
  -display none
*/

int main() {
    int sock;
    struct dn_id del_pipe;

    // 1. Create a socket for PF_INET
    sock = socket(AF_INET, SOCK_RAW, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // 2. Specify the pipe ID to delete
    memset(&del_pipe, 0, sizeof(del_pipe));
    del_pipe.id = 1;  // pipe number you want to delete

    // 3. Call setsockopt to delete the pipe
    int error;
    if ((error = setsockopt(sock, IPPROTO_IP, IP_DUMMYNET_DEL, &del_pipe, 0x7FFFFF00)) < 0) {
        printf("%d\n", error);
        printf("%d\n", errno);
        perror("setsockopt IP_DUMMYNET_DEL");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Dummynet pipe %d deleted successfully\n", del_pipe.id);

    close(sock);
    return 0;
}
