#pragma once

#ifndef ATTACK_PARAMS_H
#define ATTACK_PARAMS_H

#include <arpa/inet.h>
#include <stdint.h>

typedef struct {
    struct sockaddr_in target_addr;  
    uint32_t duration;               
    volatile uint32_t active;        
    uint32_t psize;                  
    uint16_t srcport;                
} attack_params;

typedef struct {
    struct sockaddr_in target_addr; 
    uint32_t duration;               
    volatile uint32_t active;       
    uint32_t psize;                 
    uint16_t srcport;                
    uint16_t gre_proto;             
    uint16_t gport;                 
} gre_attack_params;

#endif // ATTACK_PARAMS_H
