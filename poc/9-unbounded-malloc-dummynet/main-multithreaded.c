#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_fw.h>
#include <netinet/ip_dummynet.h>

#define NUM_THREADS 100

struct thread_arg {
    int sock;
    int pipe_id;
};

void *delete_pipe(void *arg) {
    struct thread_arg *targ = (struct thread_arg *)arg;

    struct dn_id del_pipe;
    memset(&del_pipe, 0, sizeof(del_pipe));
    del_pipe.id = targ->pipe_id;

    if (setsockopt(targ->sock, IPPROTO_IP, IP_DUMMYNET_DEL,
                   &del_pipe, 0x7FFFFF00) < 0) {
        perror("setsockopt IP_DUMMYNET_DEL");
    } else {
        printf("Thread %lu: Dummynet pipe %d deleted successfully\n",
               pthread_self(), del_pipe.id);
    }

    return NULL;
}

int main() {
    int sock = socket(AF_INET, SOCK_RAW, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    pthread_t threads[NUM_THREADS];
    struct thread_arg args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].sock = sock;      // all threads share same socket
        args[i].pipe_id = 1;      // all delete pipe 1 (or vary this if you want)
        if (pthread_create(&threads[i], NULL, delete_pipe, &args[i]) != 0) {
            perror("pthread_create");
            close(sock);
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    close(sock);
    return 0;
}
