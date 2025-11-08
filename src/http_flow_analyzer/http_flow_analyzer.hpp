#ifndef HTTP_FLOW_ANALYZER_HPP
#define HTTP_FLOW_ANALYZER_HPP

#include <pcap.h>
#include <cstdint>
#include <memory>

#include "http_flow_store.hpp"
#include "sniffer_utils.hpp"

class HttpFlowAnalyzer
{
   public:
    HttpFlowAnalyzer();
    ~HttpFlowAnalyzer();

    // Set server port for distinguishing requests (client->server) from responses (server->client)
    void setServerPort(uint16_t port) { m_server_port = port; }
    
    // Main entry point: receives raw packet and performs HTTP flow analysis
    virtual void onPacketReceived(const struct pcap_pkthdr* h, const u_char* bytes);

    // Prints summary statistics of analyzed flows
    void printStatistics();

    // Access the flow store (for statistics/export)
    const HttpFlowStore& getFlowStore() const { return m_store; }

   private:
    // Analyzes HTTP request packets (client → server)
    void analyzeRequestPacket(size_t flow_key, uint64_t timestamp_ms, 
                              const PayloadInfo& packet_info, 
                              const uint8_t* payload, size_t payload_len);
    
    // Analyzes HTTP response packets (server → client)  
    void analyzeResponsePacket(size_t flow_key, uint64_t timestamp_ms,
                               const PayloadInfo& packet_info,
                               const uint8_t* payload, size_t payload_len);

    HttpFlowStore m_store;  // Owns the flow data
    uint16_t m_server_port{0}; // Server port (must be set before processing packets)
};

#endif  // HTTP_FLOW_ANALYZER_HPP
