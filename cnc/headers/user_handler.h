#ifndef USER_HANDLER_H
#define USER_HANDLER_H

#include <pthread.h>
#include "login_utils.h"
#include "command_handler.h"
#include "botnet.h"

#define MAX_COMMAND_LENGTH 2048
#define LIGHT_BLUE "\033[1;34m"
#define YELLOW "\033[1;33m"
#define RESET "\033[0m"
#define RED "\033[1;31m"
#define BLUE "\033[1;34m"

extern int user_sockets[MAX_USERS];
extern pthread_mutex_t bot_mutex;
extern pthread_mutex_t cooldown_mutex;
extern int bot_count;
extern Bot bots[MAX_BOTS];

void* handle_client(void* arg);
void* update_title(void* arg);

#endif
