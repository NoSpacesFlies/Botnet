#ifndef COMMAND_ACTIONS_H
#define COMMAND_ACTIONS_H

#define CYAN "\033[1;36m"
#include "botnet.h"
#include "login_utils.h"

void handle_help_command(char *response);
void handle_misc_command(char *response);
void handle_attack_list_command(char *response);
void handle_opthelp_command(char *response);
void handle_clear_command(char *response);
void handle_ping_command(char *response);

void handle_bots_command(char *response);
void handle_stopall_command(const User *user, char *response);

void handle_layer3_attack_command(const User *user, const char *command, char *response);
void handle_attack_command(const User *user, const char *command, char *response);
int is_attack_command(const char *command);

void handle_user_command(const User *user, const char *command, char *response);
void handle_adduser_command(const User *user, int client_socket);
void handle_removeuser_command(const User *user, const char *command, char *response);
void handle_kickuser_command(const User *user, const char *command, char *response);

void handle_admin_command(const User *user, char *response);

#endif
