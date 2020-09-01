#include "get_addr.h"

int get_addr(u_char mac[6], u_char gate_ip[4], pcap_if_t *dev){
	PIP_ADAPTER_INFO pAdapterInfo;
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	int i;
	char *context;
	DWORD dwRetVal = 0;

	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return 1;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		
		if (strcmp(pAdapterInfo->AdapterName,
			strstr(dev->name, pAdapterInfo->AdapterName)) == 0){

			for (i = 0; i < ETHER_ADDR_LEN; i++)
				mac[i] = pAdapterInfo->Address[i]; // my mac addr
			for (i = 0; i < IP_ADDR_LEN; i++) if (gate_ip[i] != 0) break; // already set ip, skip get gateway ip
			if (i != 4) return 0;
			//gateway ip
			gate_ip[0] = atoi(strtok_s(pAdapterInfo->GatewayList.IpAddress.String, ".", &context));
			for (i = 1; i < IP_ADDR_LEN; i++)
				gate_ip[i] = atoi(strtok_s(NULL, ".", &context));

			if (pAdapterInfo)
				free(pAdapterInfo);

			return 0;
		}
	}
	else printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);

	if (pAdapterInfo)
		free(pAdapterInfo);

	return 0;
}

void get_macaddr(u_char ip[4], u_char mac[6]){
	int i;
	unsigned int j;

	PMIB_IPNET_TABLE2 pipTable = NULL;

	if (GetIpNetTable2(AF_INET, &pipTable) != NO_ERROR) {
		printf("GetIpNetTable for IPv4 table returned error\n");
		return;
	}

	for (i = 0; i < pipTable->NumEntries; i++) {

		// ip addr

		if (ip[0] != pipTable->Table[i].Address.Ipv4.sin_addr.S_un.S_un_b.s_b1) continue;
		if (ip[1] != pipTable->Table[i].Address.Ipv4.sin_addr.S_un.S_un_b.s_b2) continue;
		if (ip[2] != pipTable->Table[i].Address.Ipv4.sin_addr.S_un.S_un_b.s_b3) continue;
		if (ip[3] != pipTable->Table[i].Address.Ipv4.sin_addr.S_un.S_un_b.s_b4) continue;

		if (pipTable->Table[i].PhysicalAddressLength == 0) continue;


		for (j = 0; j < 6; j++) // mac addr
			mac[j] = (int)pipTable->Table[i].PhysicalAddress[j];
		if (j == 6) {
			FreeMibTable(pipTable);
			pipTable = NULL;
			return;
		}

	}
	FreeMibTable(pipTable);
	pipTable = NULL;

	return;
}
