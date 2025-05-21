#pragma once

#ifndef ICMP_ATTACK_H
#define ICMP_ATTACK_H

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include "attack_params.h"

void* icmp_attack(void* arg);

#endif // ICMP_ATTACK_H
