#include "headers/login_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

User users[MAX_USERS];
int user_count = 0;

void load_users() {
    FILE *file = fopen("database/logins.txt", "r");
    if (!file) return;
    user_count = 0;
    
    char rootusers[512] = {0};
    FILE *sf = fopen("options/settings.txt", "r");
    if (sf) {
        char line[128];
        while (fgets(line, sizeof(line), sf)) {
            if (strncmp(line, "rootuser:", 9) == 0) {
                sscanf(line + 9, " %511s", rootusers);
                break;
            }
        }
        fclose(sf);
    }
    
    char line[256];
    while (user_count < MAX_USERS && fgets(line, sizeof(line), file)) {
        users[user_count].is_admin = 0;
        users[user_count].is_root = 0;
        users[user_count].prefix_enabled = 0;
        char user[50], pass[50], admin_flag[16] = "";
        int maxtime = 0, maxbots = 0;
        int n = sscanf(line, "%49s %49s %d %d %15s", user, pass, &maxtime, &maxbots, admin_flag);
        if (n < 4) continue;
        strncpy(users[user_count].user, user, sizeof(users[user_count].user)-1);
        users[user_count].user[sizeof(users[user_count].user)-1] = '\0';
        strncpy(users[user_count].pass, pass, sizeof(users[user_count].pass)-1);
        users[user_count].pass[sizeof(users[user_count].pass)-1] = '\0';
        users[user_count].maxtime = maxtime;
        users[user_count].maxbots = maxbots;
        if (n == 5 && strcmp(admin_flag, "admin") == 0) {
            users[user_count].is_admin = 1;
        }
        
        if (rootusers[0] != '\0') {
            char *root_copy = malloc(strlen(rootusers) + 1);
            strcpy(root_copy, rootusers);
            char *saveptr;
            char *token = strtok_r(root_copy, ",", &saveptr);
            while (token) {
                while (*token == ' ') token++;
                char *end = token + strlen(token) - 1;
                while (end > token && *end == ' ') {
                    *end = '\0';
                    end--;
                }
                if (strcmp(user, token) == 0) {
                    users[user_count].is_root = 1;
                    break;
                }
                token = strtok_r(NULL, ",", &saveptr);
            }
            free(root_copy);
        }
        
        users[user_count].is_logged_in = 0;
        user_count++;
    }
    fclose(file);
}

int check_login(const char *user, const char *pass) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(user, users[i].user) == 0 && strcmp(pass, users[i].pass) == 0) {
            if (users[i].is_logged_in) {
                return -2;
            }
            return i;
        }
    }
    return -1;
}
