#ifndef UTIL
#define UTIL

#include "headers.h"
#include "struct.h"

pcap_if_t *find_dev();

void arp_table_update(u_char ip[4]);

void set_inf_pack(u_char *packet, input data);

void ip_input(input *str);
	
#endif