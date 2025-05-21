#pragma once

#ifndef GRE_ATTACK_H
#define GRE_ATTACK_H

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include "attack_params.h"

void* gre_attack(void* arg);

#endif // GRE_ATTACK_H
