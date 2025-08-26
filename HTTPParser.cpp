#include "HTTPParser.hpp"
#include "Parser.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <cstring>
#include <algorithm>

namespace NetworkParser {

Parser* parser = nullptr;

Stats HTTPParser::parsePacket(const uint8_t* packet, size_t length, size_t offset, Stats ip_add_stats) {
    Stats placeholder;

    if (length <= offset) {
        std::cerr << "Error: Malformed HTTP packet - insufficient data." << std::endl;
        return placeholder;
    }

    const char* httpData = reinterpret_cast<const char*>(packet + offset);
    size_t httpDataLength = length - offset;

    // Find end of headers
    const char* endOfHeaders = std::strstr(httpData, "\r\n\r\n");
    if (!endOfHeaders) {
        endOfHeaders = httpData + httpDataLength;
    }
    size_t headerLength = endOfHeaders - httpData;

    // Split into header lines
    std::vector<std::string> headerLines;
    const char* current = httpData;
    const char* end = httpData + headerLength;

    while (current < end) {
        const char* lineEnd = nullptr;
        // Look for "\r\n" first
        const char* crlf = std::strstr(current, "\r\n");
        // Look for standalone '\n'
        const char* lf = static_cast<const char*>(memchr(current, '\n', end - current));

        // Choose the closest valid line ending
        if (crlf && crlf < end) {
            lineEnd = crlf;
        } else if (lf && lf < end) {
            lineEnd = lf;
        } else {
            lineEnd = end; // No more line endings
        }

        // Extract the line (excluding the line ending)
        headerLines.emplace_back(current, lineEnd - current);

        // Advance past the line ending
        if (lineEnd == crlf) {
            current = lineEnd + 2; // Skip "\r\n"
        } else if (lineEnd == lf) {
            current = lineEnd + 1; // Skip "\n"
        } else {
            current = end; // No more lines
        }
    }

    if (headerLines.empty()) return placeholder;

    // Parse first line
    HTTPHeader httpHeader;
    std::string firstLine = headerLines[0];
    headerLines.erase(headerLines.begin());

    // Determine request/response type
    if (firstLine.compare(0, 5, "HTTP/") == 0) {
        // Parse response
        std::istringstream iss(firstLine);
        std::string version;
        iss >> version >> httpHeader.statusCode;
        std::getline(iss, httpHeader.statusMessage);
        httpHeader.statusMessage.erase(0, httpHeader.statusMessage.find_first_not_of(' '));
    } else {
        // Parse request
        std::istringstream iss(firstLine);
        iss >> httpHeader.method >> httpHeader.url >> httpHeader.httpVersion;
        httpHeader.url = sanitizeString(httpHeader.url);
       // std::cout << httpHeader.method << std::endl;
    }

    // Update statistics
    if (!httpHeader.method.empty()) {
        std::string method = toUppercase(httpHeader.method);
        request[method]++;
    }

    if (httpHeader.statusCode != 0) {
        statusCodes[httpHeader.statusCode]++;
    }

    // Parse remaining headers
    for (const auto& line : headerLines) {
        size_t colonPos = line.find(':');
        if (colonPos == std::string::npos) continue;

        std::string key = line.substr(0, colonPos);
        std::string value = line.substr(colonPos + 1);

        // Trim whitespace
        auto trim = [](std::string& s) {
            s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
                return !std::isspace(ch);
            }));
            s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
                return !std::isspace(ch);
            }).base(), s.end());
        };

        trim(key);
        trim(value);

        headerStats[key][value]++;

        // Populate known headers
        if (key == "Host") httpHeader.host = value;
        else if (key == "User-Agent") httpHeader.userAgent = value;
        else if (key == "Content-Type") httpHeader.contentType = value;
        else if (key == "Content-Length") {
            try {
                httpHeader.contentLength = std::stoi(value);
            } catch (...) {
                std::cerr << "Invalid Content-Length: " << value << std::endl;
            }
        }
    }

    if (!httpHeader.method.empty()) {
        if (!httpHeader.host.empty() && !httpHeader.url.empty()) {
            std::string sanitizedHost = sanitizeString(httpHeader.host);
            std::string sanitizedUrl = sanitizeString(httpHeader.url);
            std::string fullURL = sanitizedHost + sanitizedUrl;
            urlStats[fullURL]++;
        }
    }

    // Update global metrics
    httpTotalPackets++;
    if (httpHeader.contentLength > 0) {
        httpTotalBytes += httpHeader.contentLength;
    }

    return placeholder;
}


std::string HTTPParser::toUppercase(const std::string& str) {
    std::string upperStr = str;
    std::transform(upperStr.begin(), upperStr.end(), upperStr.begin(),
        [](unsigned char c){ return std::toupper(c); });
    return upperStr;
}


size_t HTTPParser::getOffset() const {
    return 0;  
}

// Determine the next parser based on the protocol
std::string HTTPParser::nextParser() const {
    return "None"; 
}

// Generate reports for HTTP statistics
void HTTPParser::generateReport() {

    // Generate general summary report
    std::ofstream generalFile("output-http-csv-files/http-general-summary.csv");
    if (generalFile.is_open()) {
        generalFile << "#packets,bytes,#GET,#PUT,#POST,#PATCH,#DELETE\n";
        generalFile << httpTotalPackets << ","
                  << httpTotalBytes << ","
                  << request["GET"] << ","
                  << request["PUT"] << ","
                  << request["POST"] << ","
                  << request["PATCH"] << ","
                  << request["DELETE"] << "\n";
        generalFile.close();
    } else {
        std::cerr << "Error opening http-general-summary.csv\n";
    }

    // Generate header statistics report
    std::ofstream headerFile("output-http-csv-files/http-header-stats.csv");
    if (headerFile.is_open()) {
        headerFile << "header-name,header-value,#packets\n";
        for (const auto& [headerName, values] : headerStats) {
            for (const auto& [value, count] : values) {
                headerFile << headerName << "," << value << "," << count << "\n";
            }
        }
        headerFile.close();
    } else {
        std::cerr << "Error opening http-header-stats.csv\n";
    }

    std::ofstream urlFile("output-http-csv-files/http-url-stats.csv");
    if (urlFile.is_open()) {
        urlFile << "#url,#count\n";
        for (const auto& [url, count] : urlStats) {
            urlFile << url << "," << count << "\n";
        }
    } else {
        std::cerr << "Error opening http-header-stats.csv\n";
    }
}

std::string HTTPParser::sanitizeString(const std::string& input) {
    std::string output;
        for (char c : input) {
            if (c >= 0x20 && c <= 0x7E) { 
                output += c;
            }
        }
        return output;
}


extern "C" {
    Parser* createNewParser() {
        return new HTTPParser();
    }

    void destroyParser(Parser* p) {
        delete p;
    }

    void genReport() {
        HTTPParser::generateReport();
    }

}
}  // namespace NetworkParser