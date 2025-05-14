#ifndef LOGIN_UTILS_H
#define LOGIN_UTILS_H

#define MAX_USERS 8

typedef struct {
    char user[50];
    char pass[50];
    int maxtime;
    int maxbots;
    int is_logged_in;
} User;

extern User users[MAX_USERS];
extern int user_count;

void load_users();
int check_login(const char *user, const char *pass);

#endif
