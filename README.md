# arp_spoof_with_winpcap
arp spoofing with winpcap

Headers.h > define basic header

Get_addr.h > get_addr, get_macaddr function prototype define

Send.h > send, relay_send function prototype define

Util.h > find_dev, set_inf_pack, ip_input,  arp_tabe_update function prototype define

// Lookup.h > lookup, packet_handler function prototype define

Struct.h > user structer, constant value define

Get_addr.cpp
get_addr function > check my mac addr and gateway ip
Get_macaddr function > get ip, mac addr from arp cache table


Send.cpp
send function > send packet with selected network device
relay_send function > sniffing packet send to origin destination

Util.cpp
Data_input function > data set user structer
Set_inf_pack function > set infection packet with user structer
Find_dev function > select network device and return handle
arp_tabe_update function > arp cache table update with send ping, and get mac addr

Main.cpp
input victim ip
create infection send Thread, relay Thread
run

// lookup.cpp not use;


<img width="437" alt="2020-09-01_19-29-05" src="https://user-images.githubusercontent.com/17266558/91839023-58a36780-ec89-11ea-9e94-14cf9c592ce8.png">
