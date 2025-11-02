#ifndef HTTP_FLOW_DATA_HPP
#define HTTP_FLOW_DATA_HPP

#include <cstdint>
#include <set>
#include <string>
#include <utility>
#include <vector>

// Structure to buffer packets that arrive before HTTP header
struct BufferedPacket
{
    uint32_t seq;
    std::vector<uint8_t> payload;
};

struct Data
{
    // Response tracking
    uint64_t totalBytes{0};
    uint64_t byteCount{0};
    uint64_t timestamp_ms{0};
    uint64_t last_timestamp_ms{0};
    std::set<uint32_t> tcp_seqs;
    // received byte ranges [start, end) to avoid double counting
    // use 64-bit offsets relative to server_isn to handle 32-bit seq wrap
    std::vector<std::pair<uint64_t, uint64_t>> received_ranges;
    // server initial sequence number (host order) when first response header seen
    uint32_t server_isn{0};
    bool server_isn_set{false};
    // buffer for packets that arrive before HTTP header
    std::vector<BufferedPacket> buffered_packets;
    // flag to print excess data only once per flow
    bool excess_data_dumped{false};

    // Request information
    std::string request_method;      // GET, POST, etc.
    std::string request_uri;         // /path/to/resource
    std::string request_version;     // HTTP/1.1
    std::string request_host;        // Host header value
    std::string request_user_agent;  // User-Agent header value
    std::string client_addr;         // Client IP address
    uint16_t client_port{0};         // Client port number
    std::string server_addr;         // Server IP address
    uint16_t server_port{0};         // Server port number
    uint64_t request_timestamp_ms{0}; // When request was captured on network
    bool request_captured{false};    // Whether we captured the request
};

#endif // HTTP_FLOW_DATA_HPP
