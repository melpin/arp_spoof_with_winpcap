#ifndef SEND
#define SEND

#include "struct.h"

void send(pcap_if_t *dev, u_char* packet, int pack_size);

int relay_send(pcap_if_t *d, input** str, char *power);

#endif