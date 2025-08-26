#pragma once
#include <iostream>
#include <string>
#include "Parser.hpp"

namespace NetworkParser {

static size_t httpTotalPackets = 0;
static size_t httpTotalBytes = 0;
static std::unordered_map<std::string, size_t> request;  // request to frequency (GET, POST etc.)
static std::unordered_map<int, size_t> statusCodes; // status code frequency
static std::unordered_map<std::string, std::unordered_map<std::string, size_t>> headerStats;  // header name - [header value - frequency]
static std::unordered_map<std::string, size_t> urlStats;

class HTTPParser : public Parser {
 public:
    Stats parsePacket(const uint8_t* packet, size_t length, size_t offset, Stats ip_add_stats) override;
    std::string nextParser() const override;
    static void generateReport() __attribute__((visibility("default")));
    size_t getOffset() const override;
 private:
    static std::string toUppercase(const std::string& str);
    static std::string sanitizeString(const std::string& input);
};

extern "C" {
    Parser* createNewParser();
    void destroyParser(Parser* p);
    void genReport();
}

#pragma pack(push, 1)
struct HTTPHeader {
    std::string method;        // GET, POST, etc. (for requests)
    std::string url;           // Requested URL (for requests)
    std::string httpVersion;   // HTTP/1.1, HTTP/2, etc.
    int statusCode = 0;        // Response status code (for responses)
    std::string statusMessage; // Response status message
    std::string host;          // Host header field
    std::string userAgent;     // User-Agent header
    std::string contentType;   // Content-Type header
    int contentLength = -1;    // Content-Length (if present)
};
#pragma pack(pop)
}