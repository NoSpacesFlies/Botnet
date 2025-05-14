#ifndef SOCKET_ATTACK_H
#define SOCKET_ATTACK_H

#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "attack_params.h"

void* socket_attack(void* arg);

#endif // SOCKET_ATTACK_H
