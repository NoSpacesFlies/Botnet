#pragma once

#ifndef DAEMON_H
#define DAEMON_H

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <fcntl.h>

int daemonize(int argc, char **argv);

#endif // DAEMON_H
