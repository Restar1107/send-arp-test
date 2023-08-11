#include <sys/socket.h>
#include <sys/ioctl.h>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <stdint.h>
void get_my_ip(char * ether, char ip_addr_buf[INET_ADDRSTRLEN]);
