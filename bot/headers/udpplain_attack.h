#pragma once
#ifndef UDPPLAIN_ATTACK_H
#define UDPPLAIN_ATTACK_H
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "attack_params.h"
void* udpplain_attack(void* arg);
#endif
