#pragma once
#include <iostream>
#include <string>
#include <iostream>

namespace NetworkParser {

struct Stats {
    size_t packetsIn = 0;
    size_t packetsOut = 0;
    size_t bytesIn = 0;
    size_t bytesOut = 0;
    std::string ip1 = "";
    std::string ip2 = "";
};

class Parser {
public:
    virtual ~Parser() = default;

    // Pure virtual function to parse the packet
    virtual Stats parsePacket(const uint8_t* packet, size_t length, size_t offset, Stats ip_add_stats) = 0;

    // Function to get the offset for the next parser
    virtual size_t getOffset() const { return 0; }

    // Function to determine the next parser
    virtual std::string nextParser() const { return ""; }
};

} // namespace NetworkParser