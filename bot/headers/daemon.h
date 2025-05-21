#pragma once

#ifndef DAEMON_H
#define DAEMON_H

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <fcntl.h>

void daemonize(int argc, char** argv);
void overwrite_argv(int argc, char** argv);
//Watchdog in daemon.c
int copy_file(const char *src, const char *dst);

#endif // DAEMON_H
