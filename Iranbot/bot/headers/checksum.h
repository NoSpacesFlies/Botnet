#pragma once

#ifndef CHECKSUM_H
#define CHECKSUM_H
#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>

unsigned short generic_checksum(void* b, int len);
unsigned short tcp_udp_checksum(const void* buff, size_t len, unsigned int src_addr, unsigned int dest_addr, unsigned char proto);

#endif // CHECKSUM_H
