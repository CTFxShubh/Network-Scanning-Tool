//UDP Header

#pragma once
#include <cstdint>

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t length;
    uint16_t checksum;
};
