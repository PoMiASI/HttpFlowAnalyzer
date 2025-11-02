#ifndef SNIFFER_UTILS_HPP
#define SNIFFER_UTILS_HPP

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

#include <cstddef>
#include <cstdint>
#include <string>

struct PayloadInfo
{
    size_t payload_offset;
    int payload_len;
    uint16_t eth_type;
    const struct ip* ip;
    const struct tcphdr* tcp;
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    uint16_t srcport;
    uint16_t dstport;
};

struct FlowKeyHash
{
    size_t operator()(PayloadInfo const& pi) const noexcept
    {
        // Normalize flow direction to ensure bidirectional matching:
        // Always use lower IP:port as "endpoint1" and higher as "endpoint2"
        std::string ip1 = pi.src;
        std::string ip2 = pi.dst;
        uint16_t port1 = pi.srcport;
        uint16_t port2 = pi.dstport;
        
        // Compare IPs first, then ports if IPs are equal
        bool swap = false;
        int cmp = ip1.compare(ip2);
        if (cmp > 0)
        {
            swap = true;
        }
        else if (cmp == 0 && port1 > port2)
        {
            swap = true;
        }
        
        if (swap)
        {
            std::swap(ip1, ip2);
            std::swap(port1, port2);
        }
        
        size_t h1 = std::hash<std::string>{}(ip1);
        size_t h2 = std::hash<std::string>{}(ip2);
        size_t h3 = ((size_t)port1 << 16) ^ (size_t)port2;
        return (h1 * 1315423911u) ^ (h2 << 1) ^ h3;
    }
};

// Returns true if the packet contains a full Ethernet->IPv4->TCP frame (VLAN handled)
// and fills out the PayloadInfo structure. Use h->caplen for bounds checks.
bool get_payload_info(const struct pcap_pkthdr* h, const u_char* bytes, PayloadInfo& out);
size_t get_flow_key_hash(const PayloadInfo& pi);

#endif  // SNIFFER_UTILS_HPP