#ifndef STRUCT
#define STRUCT

#include "headers.h"

#define ETHER_HEADER_LEN 14
#define IP_ADDR_LEN 4
#define INFECTION_PACKET_SIZE 60

typedef struct  eth_hdr{
	u_char   dst[ETHER_ADDR_LEN];
	u_char   src[ETHER_ADDR_LEN];
	u_short  type;
}eth_hdr;

typedef struct arphdr {
	u_int16_t htype;    /* Hardware Type           */ // 01 00
	u_int16_t ptype;    /* Protocol Type           */ // 04 06
	u_char hlen;        /* Hardware Address Length */ // 
	u_char plen;        /* Protocol Address Length */ // 
	u_int16_t oper;     /* Operation Code          */ // req ,res 인지 구분 00 00 00 01
	u_char sha[ETHER_ADDR_LEN];      /* Sender hardware address */ // 내 mac 넣어야함
	u_char spa[IP_ADDR_LEN];      /* Sender IP address       */ // 라우터 ip
	u_char tha[ETHER_ADDR_LEN];      /* Target hardware address */ // res 경우 희생자 mac, req 경우 000000
	u_char tpa[IP_ADDR_LEN];      /* Target IP address       */ // 희생자 ip
}arphdr;

typedef struct ip_header{
	u_int8_t  ver_ihl;
	u_int8_t  tos;
	u_int16_t tlen;
	u_int16_t identification;
	u_int16_t flags_fo;
	u_int8_t  ttl;
	u_int8_t  proto; // >udp, tcp type
	u_int16_t crc; // checksum
	u_int8_t saddr[IP_ADDR_LEN];
	u_int8_t daddr[IP_ADDR_LEN];
	u_int32_t   op_pad;
}ip_header;

typedef struct tcp_hdr{
	u_short sport;
	u_short dport;
	u_int seq;
	u_int ack;
	u_short reserved : 4;// ?
	u_short doff : 4; // ?
	u_char flags;
	u_short window;
	u_short check;
	u_short urgent;
}tcp_hdr;

typedef struct udp_header{
	u_short sport;
	u_short dport;
	u_short len; //2
	u_short crc;
}udp_header;

typedef struct infection_packet{
	eth_hdr ethh;
	arphdr arph;
}infection_packet;

typedef struct input {
	u_char victim_mac[ETHER_ADDR_LEN];
	u_char destination_mac[ETHER_ADDR_LEN];
	u_char my_mac[ETHER_ADDR_LEN];
	u_char victim_ip[IP_ADDR_LEN];
	u_char destination_ip[IP_ADDR_LEN];
	char data_check;
}input;

#endif