// #include <linux/if.h>
// #include <cstring>
// #include <cstdio>
// #include <pcap.h>
// #include "ethhdr.h"
// #include "arphdr.h"
// #include <sys/socket.h>
// #include <sys/ioctl.h>
// #include <unistd.h>
// #include <linux/if.h>
// #include <netdb.h>
// #include <stdio.h>
// #include <string.h>
// #include <regex>
// #include <arpa/inet.h>
// #include <fstream>
// #include <streambuf>
// #include <iostream>
// #include <thread>
// #include "get_my_mac"
// #define MAC_ADDR_LEN 6
// #define IP_ADDR_LEN 4

// #pragma pack(push, 1)
// struct EthArpPacket final {
// 	EthHdr eth_;
// 	ArpHdr arp_;
// };

// #pragma pack(pop)

// static uint8_t my_mac[6] = {0,};
// static char* my_ip[INET_ADDRSTRLEN] = {0,};

// void usage() {
// 	printf("syntax: send-arp-test <interface>\n");
// 	printf("sample: send-arp-test wlan0\n");
// }

// bool get_my_mac(const std::string& if_name, uint8_t *mac_addr_buf) {
//     std::string mac_addr;
//     std::ifstream iface("/sys/class/net/" + if_name + "/address");
//     std::string str((std::istreambuf_iterator<char>(iface)), std::istreambuf_iterator<char>());
//     if (str.length() > 0) {
//         std::string hex = regex_replace(str, std::regex(":"), "");
//         uint64_t result = stoull(hex, 0, 16);
//         for (int i = 0; i < MAC_ADDR_LEN; i++) {
//             mac_addr_buf[MAC_ADDR_LEN-i-1] = (uint8_t) ((result & ((uint64_t) 0xFF << (i * 8))) >> (i * 8));
//         }

//         return true;
//     }

//     return false;
// }


// void get_my_ip(char * ether, char ip_addr_buf[INET_ADDRSTRLEN]){
//     int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

//     struct ifreq ifr{};
//     strcpy(ifr.ifr_name, ether);
//     ioctl(fd, SIOCGIFADDR, &ifr);
//     close(fd);

    
//     strcpy(ip_addr_buf, inet_ntoa(((sockaddr_in *) &ifr.ifr_addr)->sin_addr));

//     std::cout << ip_addr_buf << std::endl;
// }


// // -------------- SHOW PACKET -------------
// void show_packet(char * packet){
//     for (int i = 0; i < 60; i++){
//         printf("%02x", (uint8_t)packet[i]);
//         if (i%16 == 15){
//             printf("\n");
//         }
//         else if(i%8 == 7){
//             printf("-");
//         }
//         else {
//             printf(" ");
//         }
//     }
// }
// // -------------- SHOW PACKET -------------



// void get_mac_arp(char *argv[4], uint8_t mac_buf){
//     char* dev = argv[1];
// 	char errbuf[PCAP_ERRBUF_SIZE];
// 	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
// 	if (handle == nullptr) {
// 		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
// 		return -1;
// 	}

// // --------------- MAKE FIRST PACKET ------
// 	EthArpPacket packet;

// 	packet.eth_.dmac_ = Mac(my_mac);
// 	packet.eth_.smac_ = Mac("FF:FF:FF:FF:FF:FF");
// 	packet.eth_.type_ = htons(EthHdr::Arp);

// 	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
// 	packet.arp_.pro_ = htons(EthHdr::Ip4);
// 	packet.arp_.hln_ = Mac::SIZE;
// 	packet.arp_.pln_ = Ip::SIZE;
// 	packet.arp_.op_ = htons(ArpHdr::Request);
// 	packet.arp_.smac_ = Mac(my_mac);
// 	packet.arp_.sip_ = htonl(Ip(my_ip));
// 	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
// 	packet.arp_.tip_ = htonl(Ip(send_ip));
// // --------------- MAKE FIRST PACKET ------


// // --------------- PCAP_SEND --------------
// 	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
// 	if (res != 0) {
// 		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
// 	}
// // --------------- PCAP_SEND --------------
    

// // --------------- PCAP_GET ---------------
//     const uint8_t * text;
//     while(1) {
//         struct pcap_pkthdr *header;
//         int res = pcap_next_ex(handle, &header, (const u_char**)(&text)); // open  (pcap_t *pcap, pcap_pkthdr **abstact info, packet const char **)
// 		if (res == 0) continue;
// 		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
// 			printf("pcap_next_e./x return %d(%s)\n", res, pcap_geterr(handle));
// 			break;
// 		}

//         // ------- DEBUG ------------------
//         show_packet((char*)text);
//         // ------- DEBUG ------------------


//         // ------- MY_CODE ----------------
//         unsigned char cap_ip[INET_ADDRSTRLEN] = {0,};
//         sprintf((char*)cap_ip, "%u.%u.%u.%u",text[0x1C],text[0x1D],text[0X1E],text[0X1F]);
//         printf("\n%02x.%02x.%02x.%02x\n",text[0x1C],text[0x1D],text[0X1E],text[0X1F]);
//         printf("%u.%u.%u.%u\n",text[0x1C],text[0x1D],text[0X1E],text[0X1F]);
//         if (memcmp(cap_ip, send_ip, strlen((char*)cap_ip))){printf("\nother packet \n");continue;}
//         else{printf(" --------------- you did it !!! ------------- \n"); break;}
//         // ------- MY_CODE ----------------

// 		printf("%u bytes captured\n", header->caplen);
//     }}

// // -------------- SEND PACKET -------------
// void send_packet(pcap_t *handle, char * inet, char *send_ip, char *target_ip){

// // --------------- MY CODE ----------------
//     uint8_t my_mac[6] = {0,};
//     get_my_mac(inet, my_mac);

//     char my_ip[INET_ADDRSTRLEN] = {0,};
//     get_my_ip(inet, my_ip);

// // --------------- MY CODE ----------------



// // --------------- MAKE FIRST PACKET ------
// 	EthArpPacket packet;

// 	packet.eth_.dmac_ = Mac(my_mac);
// 	packet.eth_.smac_ = Mac("FF:FF:FF:FF:FF:FF");
// 	packet.eth_.type_ = htons(EthHdr::Arp);

// 	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
// 	packet.arp_.pro_ = htons(EthHdr::Ip4);
// 	packet.arp_.hln_ = Mac::SIZE;
// 	packet.arp_.pln_ = Ip::SIZE;
// 	packet.arp_.op_ = htons(ArpHdr::Request);
// 	packet.arp_.smac_ = Mac(my_mac);
// 	packet.arp_.sip_ = htonl(Ip(my_ip));
// 	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
// 	packet.arp_.tip_ = htonl(Ip(send_ip));
// // --------------- MAKE FIRST PACKET ------


// // --------------- PCAP_SEND --------------
// 	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
// 	if (res != 0) {
// 		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
// 	}
// // --------------- PCAP_SEND --------------
    

// // --------------- PCAP_GET ---------------
//     const uint8_t * text;
//     while(1) {
//         struct pcap_pkthdr *header;
//         int res = pcap_next_ex(handle, &header, (const u_char**)(&text)); // open  (pcap_t *pcap, pcap_pkthdr **abstact info, packet const char **)
// 		if (res == 0) continue;
// 		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
// 			printf("pcap_next_e./x return %d(%s)\n", res, pcap_geterr(handle));
// 			break;
// 		}

//         // ------- DEBUG ------------------
//         show_packet((char*)text);
//         // ------- DEBUG ------------------


//         // ------- MY_CODE ----------------
//         unsigned char cap_ip[INET_ADDRSTRLEN] = {0,};
//         sprintf((char*)cap_ip, "%u.%u.%u.%u",text[0x1C],text[0x1D],text[0X1E],text[0X1F]);
//         printf("\n%02x.%02x.%02x.%02x\n",text[0x1C],text[0x1D],text[0X1E],text[0X1F]);
//         printf("%u.%u.%u.%u\n",text[0x1C],text[0x1D],text[0X1E],text[0X1F]);
//         if (memcmp(cap_ip, send_ip, strlen((char*)cap_ip))){printf("\nother packet \n");continue;}
//         else{printf(" --------------- you did it !!! ------------- \n"); break;}
//         // ------- MY_CODE ----------------

// 		printf("%u bytes captured\n", header->caplen);
//     }
// // --------------- PCAP_GET ---------------



// // --------------- MAKE SECOND PACKET -----
//     uint8_t cap_mac[6] = {0,};
//     memcpy(cap_mac, text+0x16, MAC_ADDR_LEN);

//     printf("target MAC: %02x:%02x:%02x:%02x:%02x:%02x", cap_mac[0], cap_mac[1], cap_mac[2], cap_mac[3], cap_mac[4], cap_mac[5]);
// 	packet.eth_.smac_ = Mac(cap_mac);

// 	packet.arp_.smac_ = Mac(my_mac);
// 	packet.arp_.sip_ = htonl(Ip(target_ip));
// 	packet.arp_.tmac_ = Mac(cap_mac);
	
// // --------------- MAKE SECOND PACKET -----


// // --------------- PCAP_SEND --------------
//     while (1) {
//         res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
//         if (res != 0) {
//             fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
//         }
//         sleep(1);
//     }
// // --------------- PCAP_SEND --------------

    
// }


// // --------------- MAIN -------------------

// int main(int argc, char* argv[]) {

// // --------------- PCAP_OPEN --------------
// 	char* dev = argv[1];
// 	char errbuf[PCAP_ERRBUF_SIZE];
// 	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
// 	if (handle == nullptr) {
// 		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
// 		return -1;
// 	}
// // --------------- PCAP_OPEN --------------
    
//     get_my_mac(argv[1], my_mac);

//     get_my_ip(argv[1], my_ip);

//     uint8_t sender_mac[MAC_ADDR_LEN] = {0,};
//     get_mac_arp(my_mac, my_ip, argv[2], sender_mac);
    
//     uint8_t target_mac[MAC_ADDR_LEN] = {0,};
//     get_mac_arp(my_mac, my_ip, argv[3], target_mac);


//     send_packet(handle, argv[1], argv[2], argv[3]);
//     send_packet(handle, argv[1], argv[3], argv[2]);

// 	pcap_close(handle);
// }
// // --------------- MAIN -------------------

