#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip_carp.h>

#define NUM_CARP_IFS 10

static const char *carp_states[] = { CARP_STATES };
void dump_bytes(const void *ptr, size_t size);

/*
Prerequisites
-------------
Host must have carp kernel module loaded

sysrc kld_list+="carp"
kldload carp
*/

int main(void) {
    int s;
    struct carpreq carpr_set;
    struct carpreq carpr_get[NUM_CARP_IFS];
    int i;
    struct ifreq ifr_set;
    struct ifreq ifr_get;

    bzero(&carpr_set, sizeof(struct carpreq));
    bzero(carpr_get, sizeof(struct carpreq));

    ifr_get.ifr_data = (caddr_t)&carpr_get;
    ifr_set.ifr_data = (caddr_t)&carpr_set;

    carpr_get[0].carpr_vhid = 0;
    carpr_get[0].carpr_count = NUM_CARP_IFS;

    strlcpy(ifr_get.ifr_name, "epair100b", sizeof(ifr_get.ifr_name));
    strlcpy(ifr_set.ifr_name, "epair100b", sizeof(ifr_set.ifr_name));

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        exit(1);
    }

    // Create carp interfaces
    for (i = 1; i < NUM_CARP_IFS + 1; i++) {
        carpr_set.carpr_vhid = i;
        carpr_set.carpr_count = 1;
        carpr_set.carpr_advbase = i;   /* default advertisement base */
        carpr_set.carpr_advskew = i;   /* skew */
        strlcpy((char*)carpr_set.carpr_key, "secret", sizeof(carpr_set.carpr_key));

        if (ioctl(s, SIOCSVH, (caddr_t)&ifr_set) == -1) {
            perror("ioctl");
            exit(1);
        }
    }

    // Enumerate carp interfaces
    if (ioctl(s, SIOCGVH, (caddr_t)&ifr_get) == -1) {
        perror("ioctl");
        exit(1);
    }

    for (i = 0; i < NUM_CARP_IFS; i++) {
        printf("Struct #%d\n", i);
        printf("Size: %zu bytes\n", sizeof(carpr_get[i]));
        printf("Raw dump:\n");
        dump_bytes(&carpr_get[i], sizeof(carpr_get[i]));
    }

    close(s);
    return 0;
}

void dump_bytes(const void *ptr, size_t size) {
    const unsigned char *p = ptr;
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", p[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n\n");
}
