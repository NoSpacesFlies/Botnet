#ifndef ATTACK_PARAMS_H
#define ATTACK_PARAMS_H

#include <arpa/inet.h>

typedef struct {
    struct sockaddr_in target_addr;
    int duration;
    int active;
} attack_params;

#endif // ATTACK_PARAMS_H
