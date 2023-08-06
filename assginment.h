#pragma once

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

unsigned char *get_mac(void)
{
    struct ifreq s;
    unsigned char mac[6] = {0,};
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, "ens33");
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        int i;
        for (i = 0; i < 6; ++i){
            sprintf((char*)(mac + i),"%02x", (unsigned char) s.ifr_addr.sa_data[i]);
            if (i < 5) printf(":");
        }
        return mac;
    }

    return NULL;
}