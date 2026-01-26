#ifndef LOGGER_H
#define LOGGER_H

void log_command(const char* user, const char* ip, const char* command);
void log_bot_join(const char* arch, const char* ip, const char* group);
void log_bot_disconnected(const char* ip, const char* arch, const char* cause);
#endif
