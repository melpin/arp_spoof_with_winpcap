#include "lookup.h"

int lookup(pcap_if_t *d)
{
	pcap_t *adhandle = NULL;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
	u_int netmask;
	
	if ((adhandle = pcap_open(d->name,
		65536,
		PCAP_OPENFLAG_PROMISCUOUS,
		1000,
		NULL,
		errbuf
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		return -1;
	}//장치에따른 패킷핸들러를 열어줌 

	if (pcap_datalink(adhandle) != DLT_EN10MB){
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		return -1;
	} // ?

	if (d->addresses != NULL) 
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else netmask = 0xffffff; //? // ?

	printf("\nlistening on %s...\n", d->description);
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

	libnet_ethernet_hdr *eth_h;
	libnet_ipv4_hdr *ip_h;
	libnet_tcp_hdr *tcp_h;

	u_char forward_packet[LIBNET_MAX_PACKET] = { 0 };
	u_char backward_packet[LIBNET_MAX_PACKET] = { 0 };

	int data_length = 0;
	int tcp_data_size = 0;
	int i = 0;

	eth_h = (libnet_ethernet_hdr*)pkt_data;
	//if (ntohs(eth_h->ether_type) != ETHERTYPE_IP) return;
	ip_h = (libnet_ipv4_hdr*)(pkt_data + sizeof(libnet_ethernet_hdr));
	//if (ip_h->ip_p != IPPROTO_TCP) return;
	tcp_h = (libnet_tcp_hdr*)(pkt_data + sizeof(libnet_ethernet_hdr) + ip_h->ip_hl);
	//header setting
	
	printf("%d\n", ip_h->ip_hl);
	printf("%d\n", tcp_h->th_off);


	tcp_data_size = sizeof(libnet_ethernet_hdr) + ip_h->ip_hl + tcp_h->th_off;
	data_length = ntohl(ip_h->ip_len) - ip_h->ip_hl - tcp_h->th_off; // 데이터 길이

	tcp_h->th_flags = tcp_h->th_flags | TH_RST;

	tcp_h->th_seq = tcp_h->th_seq + data_length;

	//-------------------------------------

	//eth_hdr *ethhdr;
	//ip_header *ih;
	//libnet_tcp_hdr *th;
	//udp_header *uh;
	//u_int ip_header_len;
	//u_short sport, dport;
	//int length = 0; //= header->len; // 패킷길이
	//int chcnt = 0; // 줄바꿈 단위
	//int i = 0;
	//ethhdr = (eth_hdr*)(pkt_data); // ethernet headr 부분부터 판단
	//ih = (ip_header *)(pkt_data + ETHER_HEADER_LEN); // Ip headr 부분부터 판단
	//ip_header_len = (ih->ver_ihl & 0xf) * 4; //ip_header 의 길이
	//
	//if (ih->proto == IPPROTO_TCP){ // 프로토콜 종류를 보고 TCP인지 UDP인지 판단
	//	printf("\t\t\t TCP\n");
	//	th = (libnet_tcp_hdr*)((u_char*)ih + ip_header_len);
	//	sport = ntohs(th->th_sport);
	//	dport = ntohs(th->th_dport);
	//	length = ntohs(ih->tlen) - ip_header_len - th->th_off;
	//	pkt_data += ip_header_len + ETHER_HEADER_LEN + th->th_off;

	//	printf("header cap len : %d\n",
	//		header->caplen - ETHER_HEADER_LEN - LIBNET_IPV4_H -
	//		(ih->proto == IPPROTO_TCP ? th->th_off : sizeof(udp_header)));
	//}
	//else if (ih->proto == IPPROTO_UDP){
	//	printf("\t\t\t UDP\n");
	//	uh = (udp_header *)((u_char*)ih + ip_header_len);
	//	sport = ntohs(uh->sport);
	//	dport = ntohs(uh->dport);
	//	length = ntohs(ih->tlen) - ip_header_len - sizeof(udp_header);
	//	pkt_data += ETHER_HEADER_LEN + ip_header_len + sizeof(udp_header);
	//}

	////MAC 출력
	//printf("------------------------packet-------------------------\n");
	////printf("Src Mac : ");
	////for (i = 0; i < ETHER_HEADER_LEN; i++){
	////	printf("%02x", ethhdr->src[i]);
	////	if (i != 5)printf(":");
	////	else printf("\n");
	////}
	////
	////printf("Dst Mac : ");
	////for (i = 0; i < ETHER_HEADER_LEN; i++){
	////	printf("%02x", ethhdr->dst[i] );
	////	if (i != 5)printf(":");
	////	else printf("\n");
	////}
	////
	//////IP출력
	////printf("Src ip : ");
	////for (i = 0; i < IP_ADDR_LEN; i++){
	////	printf("%d", ih->saddr[i]);
	////	if (i != 3) printf(".");
	////	else printf("\n");
	////}

	////printf("Dst ip : ");
	////for (i = 0; i < IP_ADDR_LEN; i++){
	////	printf("%d", ih->daddr[i]);
	////	if (i != 3) printf(".");
	////	else printf("\n");
	////}

	//////PORT 출력
	////printf("port : %d -> %d\n", sport, dport);
	////printf("\n");

	//////패킷데이터 출력
	////printf("packet data\n");
	////for(i =0; i < length; i++){
	////	printf("%02x ", pkt_data[i]);
	////	if ((++chcnt % 8) == 0)
	////		printf("\n");
	////}

	//printf("use ip totlen calc leng : %d\n", length);
	//
	//printf("\n");
	//printf("-------------------------------------------------------");
	//printf("\n\n");
	
}
