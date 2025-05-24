#include "headers/checks.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
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
    if (strncmp(cmd, "!gre", 4) == 0 && psize > 8192) return 0;
    if (strncmp(cmd, "!udpplain", 9) == 0 && psize > 1450) return 0; 
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

int is_private_ip(const char *ip) {
    unsigned int a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    
    if (a == 127 || // 127.0.0.0/8 (localhost)
        a == 10 ||  // 10.0.0.0/8 (private area)
        (a == 192 && b == 168) || // 192.168.0.0/16 (private/localhost)
        (a == 172 && b >= 16 && b <= 31) || // 172.16.0.0/12 (private)
        (a == 255 && b == 255 && c == 255 && d == 255) || // broadcast
        (a == 0) || // 0.0.0.0/8 (reserved, INADDR_ANY/self)
        (a >= 224)) // 224.0.0.0/4 (multicast) and 240.0.0.0/4 (reserved)
    {
        return 1;
    }
    return 0;
}

int is_blacklisted(const char *ip) {
    if (is_private_ip(ip)) {
        return 1;
    }

    FILE *f = fopen("database/blacklistedtargets.txt", "r");
    if (!f) return 0;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        
        char blacklisted_ip[32];
        if (sscanf(line, "%31s", blacklisted_ip) == 1) {
            if (strcmp(ip, blacklisted_ip) == 0) {
                fclose(f);
                return 1;
            }
        }
    }
    
    fclose(f);
    return 0;
}
