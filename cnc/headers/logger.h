#ifndef LOGGER_H
#define LOGGER_H

void log_command(const char* user, const char* ip, const char* command);
void log_bot_join(const char* arch, const char* ip);
#endif
