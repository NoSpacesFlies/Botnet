#ifndef COMMAND_HANDLER_H
#define COMMAND_HANDLER_H

#include <pthread.h>
#include "login_utils.h"
#include "checks.h"
#include "logger.h"

extern pthread_mutex_t bot_mutex;
extern pthread_mutex_t cooldown_mutex;
extern int global_cooldown;

void process_command(const User *user, const char *command, int client_socket, const char *user_ip);
int is_attack_command(const char *command);

#endif
