#ifndef GET_ADDR
#define GET_ADDR

#include "headers.h"
#include "struct.h"

int get_addr(u_char mac[6], u_char gate_ip[4], pcap_if_t *dev);

void get_macaddr(u_char ip[4], u_char mac[6]);


#endif // !GET_ADDR
