#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#pragma pack(push,1)
typedef struct synchdr {
    uint32_t sm_magic;
    uint8_t  sm_v;
    uint8_t  sm_cmd;
    uint8_t  sm_table;
    uint8_t  sm_pad;
    uint32_t sm_len;
} synchdr_t;
#pragma pack(pop)

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <device> <payload_len>\n", argv[0]);
        return 2;
    }

    const char *dev = argv[1];
    long payload_len = atol(argv[2]);
    if (payload_len < 0 || payload_len > 65536) {
        fprintf(stderr, "payload_len must be 0..65536\n");
        return 2;
    }

    int fd = open(dev, O_WRONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    size_t header_sz = sizeof(synchdr_t);
    size_t total_sz = header_sz + (size_t)payload_len;
    uint8_t *buf = malloc(total_sz);
    if (!buf) {
        perror("malloc");
        close(fd);
        return 1;
    }

    /* Fill payload */
    memset(buf + header_sz, 'A', payload_len);

    /* Populate header */
    synchdr_t *h = (synchdr_t *)buf;
    h->sm_magic = htonl(0x0FF51DE5u);
    h->sm_v = 4;
    h->sm_cmd = 0;
    h->sm_table = 0;
    h->sm_pad = 0;
    h->sm_len = htonl((uint32_t)payload_len);

    ssize_t w = write(fd, buf, total_sz);
    if (w == -1) {
        perror("write");
        fprintf(stderr, "errno: %d\n", errno);
    } else {
        printf("Wrote %zd bytes (header %zu + payload %ld) to %s\n",
               w, header_sz, payload_len, dev);
    }

    free(buf);
    close(fd);
    return (w == (ssize_t)total_sz) ? 0 : 3;
}
