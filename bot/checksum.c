#include "headers/checksum.h"

unsigned short generic_checksum(void* b, int len) {
    unsigned short* buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

unsigned short tcp_udp_checksum(const void* buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr, unsigned char proto) {
    const unsigned short* buf = buff;
    unsigned int sum = 0;
    size_t length = len;

    struct pseudo_header {
        in_addr_t src_addr;
        in_addr_t dest_addr;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short length;
    } pseudo_hdr;

    pseudo_hdr.src_addr = src_addr;
    pseudo_hdr.dest_addr = dest_addr;
    pseudo_hdr.placeholder = 0;
    pseudo_hdr.protocol = proto;
    pseudo_hdr.length = htons(len);

    const unsigned short* pseudo_hdr_ptr = (unsigned short*)&pseudo_hdr;

    for (int i = 0; i < sizeof(pseudo_hdr) / 2; i++)
        sum += *pseudo_hdr_ptr++;

    while (length > 1) {
        sum += *buf++;
        length -= 2;
    }

    if (length > 0) {
        sum += *(unsigned char*)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}
