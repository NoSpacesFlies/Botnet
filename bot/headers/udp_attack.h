#ifndef UDP_ATTACK_H
#define UDP_ATTACK_H

#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <stddef.h>
#include "attack_params.h"

void* udp_attack(void* arg);

#endif // UDP_ATTACK_H
