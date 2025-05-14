#ifndef SYN_ATTACK_H
#define SYN_ATTACK_H

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "attack_params.h"

void* syn_attack(void* arg);

#endif // SYN_ATTACK_H
