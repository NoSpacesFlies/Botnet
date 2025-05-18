#ifndef KILLER_H
#define KILLER_H

#define GAFGYT_COUNT 10
static const char *GAFGYT_PROCS[] = {
    "yakuza.*",
    "axis.*",
    "sora.*",
    "condi.*",
    "mirai.*",
    "tsunami.*",
    "kaiten.*",
    "hajime.*",
    "masuta.*",
    "josho.*",
};

void start_killer(void);
void stop_killer(void);

#endif // KILLER_H
