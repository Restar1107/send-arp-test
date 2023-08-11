#include "get_my_mac.h"

bool get_my_mac(const std::string& if_name, uint8_t mac_addr_buf[6]) {
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