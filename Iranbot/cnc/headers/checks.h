#ifndef CHECKS_H
#define CHECKS_H
int validate_ip(const char *ip);
int validate_port(int port);
int validate_psize(int psize, const char *cmd);
int is_valid_int(const char *str);
int validate_srcport(int srcport);
int is_private_ip(const char *ip);
int is_blacklisted(const char *ip);
#endif