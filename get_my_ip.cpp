#include "get_my_ip.h"


void get_my_ip(char * ether, char ip_addr_buf[INET_ADDRSTRLEN]){
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    struct ifreq ifr{};
    strcpy(ifr.ifr_name, ether);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    
    strcpy(ip_addr_buf, inet_ntoa(((sockaddr_in *) &ifr.ifr_addr)->sin_addr));

    std::cout << ip_addr_buf << std::endl;
}