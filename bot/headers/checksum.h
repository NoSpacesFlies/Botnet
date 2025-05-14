#ifndef CHECKSUM_H
#define CHECKSUM_H
#include <stddef.h>
#include <netinet/in.h>

unsigned short generic_checksum(void* b, int len);
unsigned short tcp_udp_checksum(const void* buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr, unsigned char proto);

#endif // CHECKSUM_H
