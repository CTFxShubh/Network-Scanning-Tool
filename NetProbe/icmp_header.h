//ICMP Header File

#pragma once
#include <cstdint>

struct icmphdr 
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};
