#include "http_flow_analyzer.hpp"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pcap.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "http_flow_statistics.hpp"
#include "picohttpparser.h"
#include "sniffer_utils.hpp"

constexpr uint64_t MS_PER_SECOND = 1000;  // 1000 milliseconds in 1 second

HttpFlowAnalyzer::HttpFlowAnalyzer() {}

HttpFlowAnalyzer::~HttpFlowAnalyzer() {}

static inline uint64_t ts_to_ms(const struct timeval& tv)
{
    return static_cast<uint64_t>(tv.tv_sec) * MS_PER_SECOND +
           static_cast<uint64_t>(tv.tv_usec) / MS_PER_SECOND;
}

void HttpFlowAnalyzer::onPacketReceived(const struct pcap_pkthdr* hdr, const u_char* bytes)
{
    PayloadInfo payload_info;
    if (!get_payload_info(hdr, bytes, payload_info))
    {
        return;
    }

    const u_char* payload = bytes + payload_info.payload_offset;
    int payload_len = payload_info.payload_len;
    uint64_t ts_ms = ts_to_ms(hdr->ts);

    // Skip ACK or any other TCP packets with no payload
    if (payload_len <= 0)
    {
        return;
    }

    size_t key_hash = get_flow_key_hash(payload_info);

    // From client to server (destination port 8080) - HTTP request
    if (payload_info.dstport == 8080)
    {
        analyzeRequestPacket(key_hash, ts_ms, payload_info, payload,
                             static_cast<size_t>(payload_len));
    }
    // From server to client (source port 8080) - HTTP response
    else if (payload_info.srcport == 8080)
    {
        analyzeResponsePacket(key_hash, ts_ms, payload_info, payload,
                              static_cast<size_t>(payload_len));
    }
}

void HttpFlowAnalyzer::printStatistics()
{
    HttpFlowStatistics::printSummary(m_store);
}

void HttpFlowAnalyzer::analyzeRequestPacket(size_t flow_key, uint64_t timestamp_ms,
                                            const PayloadInfo& packet_info, const uint8_t* payload,
                                            size_t payload_len)
{
    // ignore empty payloads
    if (payload_len <= 0)
    {
        return;
    }

    const char* cbuf = reinterpret_cast<const char*>(payload);

    // Get or create flow entry
    Data& entry = m_store.map()[flow_key];
    if (entry.timestamp_ms == 0)
    {
        entry.timestamp_ms = timestamp_ms;
    }
    entry.last_timestamp_ms = timestamp_ms;

    // Search for ALL HTTP requests in this packet (HTTP pipelining)
    // Look for "GET " at start of packet or after "\r\n\r\n" (end of previous request)
    size_t search_offset = 0;
    int request_count = 0;

    while (search_offset < payload_len)
    {
        const char* request_start = nullptr;
        size_t remaining = payload_len - search_offset;

        // First request in packet - starts at beginning
        if (search_offset == 0 && remaining >= 3 && strncmp(cbuf, "GET", 3) == 0)
        {
            request_start = cbuf;
            std::cout << "DBG: Found GET at start of packet (offset=0)" << "\n";
        }
        // Subsequent requests - look for "\r\n\r\nGET " pattern
        else if (remaining >= 7)
        {
            // Search for pattern "\r\n\r\nGET "
            for (size_t i = search_offset; i <= payload_len - 7; ++i)
            {
                if (cbuf[i] == '\r' && cbuf[i + 1] == '\n' && cbuf[i + 2] == '\r' &&
                    cbuf[i + 3] == '\n' && cbuf[i + 4] == 'G' && cbuf[i + 5] == 'E' &&
                    cbuf[i + 6] == 'T')
                {
                    request_start = cbuf + i + 4;  // Start of "GET"
                    search_offset = i + 4;
                    std::cout << "DBG: Found GET after \\r\\n\\r\\n at offset=" << (i + 4) << "\n";
                    break;
                }
            }
        }

        if (request_start)
        {
            size_t request_remaining = payload_len - (request_start - cbuf);
            int minor_version = -1;
            phr_header headers[100];
            size_t num_headers = sizeof(headers) / sizeof(headers[0]);
            const char* method = nullptr;
            size_t method_len = 0;
            const char* path = nullptr;
            size_t path_len = 0;

            int ret = phr_parse_request(request_start, request_remaining, &method, &method_len,
                                        &path, &path_len, &minor_version, headers, &num_headers, 0);

            if (ret > 0)
            {
                request_count++;
                
                // Store request information (only first request per flow for now)
                if (!entry.request_captured)
                {
                    entry.request_method = std::string(method, method_len);
                    entry.request_uri = std::string(path, path_len);
                    entry.request_version = std::string("HTTP/1.") + std::to_string(minor_version);
                    entry.request_timestamp_ms = timestamp_ms;
                    
                    // Store client and server addresses/ports
                    entry.client_addr = std::string(packet_info.src);
                    entry.client_port = packet_info.srcport;
                    entry.server_addr = std::string(packet_info.dst);
                    entry.server_port = packet_info.dstport;
                    
                    // Extract Host and User-Agent headers
                    for (size_t i = 0; i < num_headers; ++i)
                    {
                        std::string hdr_name(headers[i].name, headers[i].name_len);
                        std::string hdr_value(headers[i].value, headers[i].value_len);
                        
                        if (hdr_name == "Host" || hdr_name == "host")
                        {
                            entry.request_host = hdr_value;
                        }
                        else if (hdr_name == "User-Agent" || hdr_name == "user-agent")
                        {
                            entry.request_user_agent = hdr_value;
                        }
                    }
                    
                    entry.request_captured = true;
                }
                
                std::cout << "HTTP Request: " << std::string(method, method_len) << " "
                          << std::string(path, path_len) << " flow=" << flow_key << "\n";
                // Move past this request to find next one
                search_offset = (request_start - cbuf) + ret;
            }
            else if (ret == -2)
            {
                std::cout << "HTTP request incomplete (need more bytes)" << "\n";
                break;  // Can't continue searching if request is incomplete
            }
            else
            {
                std::cout << "HTTP request parse error" << "\n";
                break;
            }
        }
        else
        {
            break;  // No more requests found
        }
    }

    if (request_count > 1)
    {
        std::cout << "⚠️  PIPELINING DETECTED: " << request_count << " requests in one TCP packet!"
                  << "\n";
    }
}

void HttpFlowAnalyzer::analyzeResponsePacket(size_t flow_key, uint64_t timestamp_ms,
                                             const PayloadInfo& packet_info, const uint8_t* payload,
                                             size_t payload_len)
{
    // ignore empty payloads
    if (payload_len == 0)
        return;

    const char* cbuf = reinterpret_cast<const char*>(payload);

    // Check if payload starts with HTTP response header
    const char* http_start = nullptr;
    size_t http_offset = 0;

    // HTTP response headers start with "HTTP/" (5 chars minimum)
    if (payload_len >= 5 && cbuf[0] == 'H' && cbuf[1] == 'T' && cbuf[2] == 'T' && cbuf[3] == 'P' &&
        cbuf[4] == '/')
    {
        http_start = cbuf;
        http_offset = 0;
    }

    // Also check if we have existing flow with buffered packets waiting for header
    auto it = m_store.map().find(flow_key);
    bool has_existing_flow = (it != m_store.map().end());

    // If no HTTP header and no existing flow, ignore this packet (likely retransmission after flow
    // completed)
    if (!http_start && !has_existing_flow)
    {
        std::cout << "DBG: Ignoring packet for flow=" << flow_key
                  << " (no HTTP header, flow already complete or not started yet)"
                  << " seq=" << ntohl(packet_info.tcp->th_seq) << " payload_len=" << payload_len
                  << "\n";
        return;
    }

    // Now we can safely create/get the flow entry
    Data& entry = m_store.map()[flow_key];
    if (entry.timestamp_ms == 0)
    {
        entry.timestamp_ms = timestamp_ms;
    }
    entry.last_timestamp_ms = timestamp_ms;

    int minor_version = -1;
    int status = 0;
    phr_header headers[100];
    size_t num_headers = sizeof(headers) / sizeof(headers[0]);
    const char* msg = nullptr;
    size_t msg_len = 0;
    int ret = -1;

    if (http_start)
    {
        // Found "HTTP/" - try to parse response header from this position
        ret = phr_parse_response(http_start, payload_len - http_offset, &minor_version, &status,
                                 &msg, &msg_len, headers, &num_headers, 0);

        if (ret > 0)
        {
            // Successfully parsed HTTP response header
            std::cout << "HTTP Response: flow=" << flow_key << " status=" << status;
            if (msg && msg_len > 0)
                std::cout << " msg=" << std::string(msg, msg_len);
            std::cout << " headers=" << num_headers << "\n";
            for (size_t i = 0; i < num_headers; ++i)
            {
                std::string name(headers[i].name != nullptr ? headers[i].name : "",
                                 headers[i].name_len);
                std::string value(headers[i].value != nullptr ? headers[i].value : "",
                                  headers[i].value_len);
                std::cout << "  " << name << ": " << value << "\n";
                if (name == "Content-Length")
                {
                    entry.totalBytes = std::stoull(value);
                }
            }

            // seq and offsets (wrap-safe relative to server_isn)
            uint32_t seq32 = ntohl(packet_info.tcp->th_seq);

            // Calculate sequence number at the HTTP header start position in this packet
            // If HTTP header was found at offset http_offset in payload, adjust seq accordingly
            uint32_t header_seq = seq32 + static_cast<uint32_t>(http_offset);

            // If we successfully parsed a response header and already have a server_isn set,
            // this means we're seeing a NEW response (persistent connection / pipelining).
            // First, try to finalize the old response by processing any buffered packets with old
            // server_isn
            if (entry.server_isn_set)
            {
                std::cout << "DBG: new HTTP response header detected for flow=" << flow_key
                          << " old_server_isn=" << entry.server_isn << " new_seq=" << header_seq
                          << " old_totalBytes=" << entry.totalBytes
                          << " old_byteCount=" << entry.byteCount << "\n";

                // Process any buffered packets that belong to the OLD response (before reset)
                if (!entry.buffered_packets.empty())
                {
                    std::cout << "DBG: processing " << entry.buffered_packets.size()
                              << " buffered packets from OLD response before reset" << "\n";

                    for (const auto& buffered : entry.buffered_packets)
                    {
                        // Compute offset relative to OLD server_isn
                        uint32_t delta = static_cast<uint32_t>(
                            buffered.seq - static_cast<uint32_t>(entry.server_isn));
                        uint64_t start_off = static_cast<uint64_t>(delta);
                        uint64_t len64 = static_cast<uint64_t>(buffered.payload.size());
                        uint64_t end_off = start_off + len64;

                        // Track maximum received offset
                        if (end_off > entry.byteCount)
                        {
                            entry.byteCount = end_off;
                        }

                        // Keep ranges for debugging
                        entry.received_ranges.emplace_back(start_off, end_off);

                        std::cout << "DBG: processed OLD buffered packet seq=" << buffered.seq
                                  << " start_off=" << start_off << " len=" << len64 << "\n";
                    }
                }

                // Check if old response is complete and report it
                if (entry.totalBytes > 0 && entry.byteCount >= entry.totalBytes)
                {
                    std::cout << "DBG: OLD response complete: totalBytes=" << entry.totalBytes
                              << " byteCount=" << entry.byteCount << "\n";
                }
                else if (entry.totalBytes > 0)
                {
                    std::cout << "DBG: OLD response INCOMPLETE: totalBytes=" << entry.totalBytes
                              << " byteCount=" << entry.byteCount
                              << " missing=" << (entry.totalBytes - entry.byteCount) << "\n";
                }

                // Now reset for NEW response
                std::cout << "DBG: resetting received_ranges and byteCount for NEW response"
                          << "\n";
                entry.received_ranges.clear();
                entry.byteCount = 0;
                entry.excess_data_dumped = false;  // Reset for new response
                entry.buffered_packets.clear();    // Clear buffer for new response
            }
            // Set/update server_isn to sequence at body start (after HTTP headers)
            // Body should start at offset 0 in our accounting (relative to Content-Length)
            uint32_t body_offset = static_cast<uint32_t>(ret);
            if (body_offset > payload_len - http_offset)
                body_offset = static_cast<uint32_t>(payload_len - http_offset);

            // server_isn should point to the first body byte, NOT the header start
            entry.server_isn = header_seq + body_offset;
            entry.server_isn_set = true;

            // Process buffered packets now that we know server_isn
            if (!entry.buffered_packets.empty())
            {
                std::cout << "DBG: processing " << entry.buffered_packets.size()
                          << " buffered packets for flow=" << flow_key << "\n";

                // Keep track of which buffered packets should be reprocessed later
                std::vector<BufferedPacket> packets_for_next_response;

                for (const auto& buffered : entry.buffered_packets)
                {
                    // Compute offset relative to server_isn
                    uint32_t delta = static_cast<uint32_t>(buffered.seq -
                                                           static_cast<uint32_t>(entry.server_isn));
                    uint64_t start_off = static_cast<uint64_t>(delta);
                    uint64_t len64 = static_cast<uint64_t>(buffered.payload.size());
                    uint64_t end_off = start_off + len64;

                    // Check if offset is reasonable (< 4GB suggests wraparound - packet belongs to
                    // NEXT response) Typical HTTP responses are < 100MB, so > 4GB means wraparound
                    if (start_off > 4000000000ULL)
                    {
                        std::cout << "DBG: buffered packet seq=" << buffered.seq
                                  << " has huge offset=" << start_off << " (wraparound detected)"
                                  << " - keeping for next response" << "\n";
                        packets_for_next_response.push_back(buffered);
                        continue;
                    }

                    // Track maximum received offset
                    if (end_off > entry.byteCount)
                    {
                        entry.byteCount = end_off;
                    }

                    // Keep ranges for debugging
                    entry.received_ranges.emplace_back(start_off, end_off);

                    std::cout << "DBG: processed buffered packet seq=" << buffered.seq
                              << " start_off=" << start_off << " len=" << len64 << "\n";
                }

                // Replace buffer with packets that belong to next response
                entry.buffered_packets = packets_for_next_response;
                if (!packets_for_next_response.empty())
                {
                    std::cout << "DBG: kept " << packets_for_next_response.size()
                              << " buffered packets for next response (wraparound detected)"
                              << "\n";
                }
            }

            // Body starts at offset 0 (relative to server_isn which now points to body start)
            uint64_t body_start_off = 0;
            uint64_t body_len = static_cast<uint64_t>(payload_len - http_offset) -
                                static_cast<uint64_t>(body_offset);
            uint64_t body_end_off = body_start_off + body_len;

            // Simple approach: track maximum received offset (like a real client)
            // This gives 100% accuracy as we count bytes from start to furthest point
            uint64_t old_byteCount = entry.byteCount;
            if (body_end_off > entry.byteCount)
            {
                entry.byteCount = body_end_off;
            }
            uint64_t added = entry.byteCount - old_byteCount;

            // Still keep ranges for debugging
            auto& ranges = entry.received_ranges;
            ranges.emplace_back(body_start_off, body_end_off);

            // debug log
            std::cout << "DBG: ts=" << timestamp_ms << " flow=" << flow_key
                      << " 5-tuple=" << packet_info.src << ":" << packet_info.srcport << "->"
                      << packet_info.dst << ":" << packet_info.dstport << " seq=" << seq32
                      << " server_isn=" << entry.server_isn << " ret(header_len)=" << ret
                      << " payload_len=" << payload_len << " body_start_off=" << body_start_off
                      << " added=" << added << " totalByteCount=" << entry.byteCount
                      << " totalBytesHdr=" << entry.totalBytes << "\n";
        }
        else
        {
            std::cout << "HTTP response incomplete (need more bytes)" << "\n";
        }
    }
    else
    {
        // HTTP response parse error (ret < 0 and ret != -2) - treat as non-header body packet
        uint32_t seq32 = ntohl(packet_info.tcp->th_seq);

        // If we haven't seen a server_isn yet, buffer this packet for later processing
        if (!entry.server_isn_set)
        {
            // Buffer this packet - we'll process it when we get the HTTP header
            BufferedPacket buffered;
            buffered.seq = seq32;
            buffered.payload.assign(payload, payload + payload_len);
            entry.buffered_packets.push_back(buffered);

            std::cout << "DBG: buffering pre-header packet seq=" << seq32
                      << " payload_len=" << payload_len << " for flow=" << flow_key
                      << " (total buffered: " << entry.buffered_packets.size() << ")" << "\n";
            return;
        }

        // Compute offset relative to server_isn (32-bit wrap-safe)
        uint32_t delta2 = static_cast<uint32_t>(seq32 - static_cast<uint32_t>(entry.server_isn));
        uint64_t start_off = static_cast<uint64_t>(delta2);
        uint64_t len64 = static_cast<uint64_t>(payload_len);
        uint64_t end_off = start_off + len64;

        // Simple approach: track maximum received offset
        uint64_t old_byteCount = entry.byteCount;
        if (end_off > entry.byteCount)
        {
            entry.byteCount = end_off;
        }
        uint64_t added = entry.byteCount - old_byteCount;

        // Still keep ranges for debugging
        auto& ranges = entry.received_ranges;
        ranges.emplace_back(start_off, end_off);

        // debug log for non-header packets
        std::cout << "DBG: ts=" << timestamp_ms << " flow=" << flow_key
                  << " 5-tuple=" << packet_info.src << ":" << packet_info.srcport << "->"
                  << packet_info.dst << ":" << packet_info.dstport << " seq=" << seq32
                  << " payload_len=" << payload_len << " start_off=" << start_off
                  << " added=" << added << " totalByteCount=" << entry.byteCount
                  << " totalBytesHdr=" << entry.totalBytes << "\n";
    }

    // Sanity alarm: byteCount should not exceed totalBytes. If it does, print a warning and dump
    // ranges.
    if (entry.totalBytes > 0 && entry.byteCount > entry.totalBytes)
    {
        std::cout << "ALARM: byteCount(" << entry.byteCount << ") > Content-Length("
                  << entry.totalBytes << ") for flow=" << flow_key << "\n";

        // Calculate how many excess bytes we have
        uint64_t excess_bytes = entry.byteCount - entry.totalBytes;
        std::cout << "ALARM: excess bytes = " << excess_bytes << "\n";

        // Dump current packet details on first alarm for this flow
        if (!entry.excess_data_dumped)
        {
            std::cout << "ALARM: ===== FIRST PACKET CAUSING EXCESS FOR FLOW " << flow_key
                      << " =====" << "\n";
            std::cout << "ALARM: Current packet: payload_len=" << payload_len << " bytes"
                      << "\n";

            if (payload_len > 0)
            {
                uint32_t seq32 = ntohl(packet_info.tcp->th_seq);
                uint32_t delta =
                    static_cast<uint32_t>(seq32 - static_cast<uint32_t>(entry.server_isn));
                uint64_t packet_start_off = static_cast<uint64_t>(delta);

                std::cout << "ALARM: Packet starts at offset=" << packet_start_off
                          << ", ends at=" << (packet_start_off + payload_len) << "\n";
                std::cout << "ALARM: Content-Length boundary at offset=" << entry.totalBytes
                          << "\n";

                // Dump first 200 bytes of this packet
                size_t dump_len = std::min(payload_len, (size_t)200);
                std::cout << "ALARM: First " << dump_len
                          << " bytes of packet payload (hex+ASCII):" << "\n";

                for (size_t i = 0; i < dump_len; i += 16)
                {
                    std::cout << "ALARM:   ";
                    // Hex dump
                    for (size_t j = 0; j < 16 && (i + j) < dump_len; ++j)
                    {
                        printf("%02x ", payload[i + j]);
                    }
                    // Padding
                    for (size_t j = dump_len - i; j < 16 && j > 0; ++j)
                    {
                        std::cout << "   ";
                    }
                    std::cout << " | ";
                    // ASCII dump
                    for (size_t j = 0; j < 16 && (i + j) < dump_len; ++j)
                    {
                        char c = payload[i + j];
                        std::cout << (c >= 32 && c <= 126 ? c : '.');
                    }
                    std::cout << "\n";
                }

                // If this packet crosses the Content-Length boundary, show where excess starts
                if (packet_start_off < entry.totalBytes &&
                    packet_start_off + payload_len > entry.totalBytes)
                {
                    uint64_t excess_offset_in_packet = entry.totalBytes - packet_start_off;
                    std::cout << "ALARM: Excess data starts at byte " << excess_offset_in_packet
                              << " within this packet" << "\n";

                    if (excess_offset_in_packet < payload_len)
                    {
                        const uint8_t* excess_data = payload + excess_offset_in_packet;
                        size_t excess_len = payload_len - excess_offset_in_packet;

                        // Check if excess starts with "HTTP/"
                        if (excess_len >= 5)
                        {
                            const char* excess_str = reinterpret_cast<const char*>(excess_data);
                            if (excess_str[0] == 'H' && excess_str[1] == 'T' &&
                                excess_str[2] == 'T' && excess_str[3] == 'P' &&
                                excess_str[4] == '/')
                            {
                                std::cout
                                    << "⚠️  FOUND: Next HTTP response header starts in this packet!"
                                    << "\n";
                                std::cout << "⚠️  HTTP pipelining/keep-alive detected\n";
                            }
                        }
                    }
                }
            }

            std::cout << "ALARM: ===== END EXCESS DUMP =====" << "\n";
            entry.excess_data_dumped = true;
        }

        auto& ranges = entry.received_ranges;
        std::cout << "ALARM: ranges_count=" << ranges.size() << "\n";
        for (size_t i = 0; i < ranges.size(); ++i)
        {
            std::cout << "ALARM: range[" << i << "]=" << ranges[i].first << "-" << ranges[i].second
                      << "\n";
        }
    }

    if (entry.totalBytes > 0 && entry.byteCount >= entry.totalBytes)
    {
        // Flow is complete
        std::cout << "Flow complete: totalBytes=" << entry.totalBytes
                  << " byteCount=" << entry.byteCount << "\n";
        // dump ranges summary (first/last few ranges)
        auto& ranges = entry.received_ranges;
        std::cout << "DBG: flow=" << flow_key << " ranges_count=" << ranges.size() << "\n";
        size_t N = ranges.size();
        size_t show = 5;
        for (size_t i = 0; i < std::min(show, N); ++i)
        {
            std::cout << "DBG: range[" << i << "]=" << ranges[i].first << "-" << ranges[i].second
                      << "\n";
        }
        if (N > show * 2)
        {
            std::cout << "DBG: ... (" << (N - show * 2) << " ranges elided) ...\n";
        }
        for (size_t i = (N > show ? N - show : show); i < N; ++i)
        {
            if (i >= show)
                std::cout << "DBG: range[" << i << "]=" << ranges[i].first << "-"
                          << ranges[i].second << "\n";
        }
        m_store.erase(flow_key);
    }
}
