#ifndef LOOKUP
#define LOOKUP

#include "headers.h"
#include "struct.h"

int lookup(pcap_if_t *d);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

#endif