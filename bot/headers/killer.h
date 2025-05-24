#pragma once

#ifndef KILLER_H
#define KILLER_H

#include <limits.h>

#ifndef PID_MAX
#define PID_MAX 32768
#endif

#define GAFGYT_COUNT 10
extern const char *GAFGYT_PROCS[GAFGYT_COUNT];

void start_killer(void);
void stop_killer(void);

#endif // KILLER_H
