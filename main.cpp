#include <linux/if.h>
#include <cstring>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <regex>
#include <arpa/inet.h>
#include <fstream>
#include <streambuf>
#include <iostream>
#define MAC_ADDR_LEN 6

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};


void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

bool get_mac_address(const std::string& if_name, uint8_t *mac_addr_buf) {
    std::string mac_addr;
    std::ifstream iface("/sys/class/net/" + if_name + "/address");
    std::string str((std::istreambuf_iterator<char>(iface)), std::istreambuf_iterator<char>());
    if (str.length() > 0) {
        std::string hex = regex_replace(str, std::regex(":"), "");
        uint64_t result = stoull(hex, 0, 16);
        for (int i = 0; i < MAC_ADDR_LEN; i++) {
            mac_addr_buf[MAC_ADDR_LEN-i-1] = (uint8_t) ((result & ((uint64_t) 0xFF << (i * 8))) >> (i * 8));
        }

        return true;
    }

    return false;
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void get_ip_addr(char * ether, char ip_addr_buf[INET_ADDRSTRLEN]){
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    struct ifreq ifr{};
    strcpy(ifr.ifr_name, ether);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    
    strcpy(ip_addr_buf, inet_ntoa(((sockaddr_in *) &ifr.ifr_addr)->sin_addr));

    std::cout << ip_addr_buf << std::endl;
}




// --------------- MAIN -------------------

int main(int argc, char* argv[]) {


// --------------- PCAP_OPEN --------------
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
// --------------- PCAP_OPEN --------------



// --------------- MY CODE ----------------
    uint8_t my_mac[6] = {0,};
    get_mac_address(argv[1], my_mac);

    char my_ip[INET_ADDRSTRLEN] = {0,};
    get_ip_addr(argv[1], my_ip);

// --------------- MY CODE ----------------



// --------------- MAKE FIRST PACKET ------
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(my_mac);
	packet.eth_.smac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac);
	packet.arp_.sip_ = htonl(Ip(my_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(argv[2]));
// --------------- MAKE FIRST PACKET ------


// --------------- PCAP_SEND --------------
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
// --------------- PCAP_SEND --------------


// --------------- PCAP_GET ---------------
    const char * text;
    while(1) {
        struct pcap_pkthdr *header;
        int res = pcap_next_ex(handle, &header, (const u_char**)(&text)); // open  (pcap_t *pcap, pcap_pkthdr **abstact info, packet const char **)
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_e./x return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

        // ------- MY_CODE ----------------
        unsigned char cap_ip[INET_ADDRSTRLEN] = {0,};
        sprintf((char*)cap_ip, "%u.%u.%u.%u",text[0],text[1],text[2],text[3]);
        if (strncmp((char *)cap_ip, argv[2], INET_ADDRSTRLEN)){printf("other packet \n");continue;}
        else{break;}


        // ------- MY_CODE ----------------

		printf("%u bytes captured\n", header->caplen);
    }
// --------------- PCAP_GET ---------------



// --------------- MAKE SECOND PACKET -----
    uint8_t cap_mac[6] = {0,};
    memcpy(cap_mac, (char *)(text+0x16), MAC_ADDR_LEN);
	packet.eth_.dmac_ = Mac(cap_mac);
	packet.eth_.smac_ = Mac(my_mac);
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(cap_mac);
	packet.arp_.sip_ = htonl(Ip(argv[2]));
	packet.arp_.tmac_ = Mac(my_mac);
	packet.arp_.tip_ = htonl(Ip(argv[3]));
// --------------- MAKE SECOND PACKET -----


// --------------- PCAP_SEND --------------
	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
// --------------- PCAP_SEND --------------

	pcap_close(handle);
}
