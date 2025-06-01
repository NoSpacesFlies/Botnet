#include "headers/command_actions.h"
#include <stdio.h>
void handle_admin_command(const User *user, char *response) {
    if (!user->is_admin) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Only admins can use !admin command\r\n" RESET);
        return;
    }
    
    snprintf(response, MAX_COMMAND_LENGTH,
             PINK "Admin Commands:\r\n"
             "!adduser - Add a new user\r\n"
             "!removeuser <username> - Remove a user\r\n"
             "!kickuser <username> - Kick a connected user\r\n" RESET);
}
