#ifndef DAEMON_H
#define DAEMON_H

void daemonize(int argc, char** argv);
void overwrite_argv(int argc, char** argv);

#endif // DAEMON_H
