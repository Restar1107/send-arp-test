#include <string.h>
#include <iostream>
#include <fstream>
#include <regex>
#include <stdint.h>
#define MAC_ADDR_LEN 6 

bool get_my_mac(const std::string& if_name, uint8_t *mac_addr_buf);