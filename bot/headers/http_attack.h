#ifndef HTTP_ATTACK_H
#define HTTP_ATTACK_H

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include "attack_params.h"

void* http_attack(void* arg);

#endif // HTTP_ATTACK_H
