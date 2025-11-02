#include "sniffer_utils.hpp"

#include <cstring>

bool get_payload_info(const struct pcap_pkthdr* h, const u_char* bytes, PayloadInfo& out)
{
    const size_t caplen = h->caplen;
    if (caplen < sizeof(struct ether_header))
    {
        return false;
    }
    const struct ether_header* eth = reinterpret_cast<const struct ether_header*>(bytes);
    uint16_t eth_type = ntohs(eth->ether_type);
    size_t offset = sizeof(struct ether_header);

    // VLAN
    if (eth_type == ETHERTYPE_VLAN)
    {
        if (caplen < offset + 4)
        {
            return false;
        }
        eth_type = ntohs(*(reinterpret_cast<const uint16_t*>(bytes + offset + 2)));
        offset += 4;
    }
    if (eth_type != ETHERTYPE_IP)
    {
        return false;
    }
    if (caplen < offset + sizeof(struct ip))
    {
        return false;
    }

    const struct ip* ip = reinterpret_cast<const struct ip*>(bytes + offset);
    if (ip->ip_v != 4 || ip->ip_p != IPPROTO_TCP)
    {
        return false;
    }

    uint16_t ip_off = ntohs(ip->ip_off);
    if ((ip_off & 0x1fff) != 0)
    {
        return false;  // fragmented
    }

    int ip_header_len = ip->ip_hl * 4;
    if (ip_header_len < 20)
    {
        return false;
    }
    if (caplen < offset + static_cast<size_t>(ip_header_len) + sizeof(struct tcphdr))
    {
        return false;
    }

    const struct tcphdr* tcp =
        reinterpret_cast<const struct tcphdr*>(bytes + offset + ip_header_len);
    int tcp_header_len = tcp->th_off * 4;
    if (tcp_header_len < 20)
    {
        return false;
    }
    if (caplen < offset + static_cast<size_t>(ip_header_len + tcp_header_len))
    {
        return false;
    }

    size_t payload_offset = offset + ip_header_len + tcp_header_len;
    if (payload_offset > caplen)
    {
        return false;
    }
    int payload_len = static_cast<int>(caplen - payload_offset);

    out.payload_offset = payload_offset;
    out.payload_len = payload_len;
    out.eth_type = eth_type;
    out.ip = ip;
    out.tcp = tcp;
    out.srcport = ntohs(tcp->th_sport);
    out.dstport = ntohs(tcp->th_dport);

    // copy ip strings
    memset(out.src, 0, sizeof(out.src));
    memset(out.dst, 0, sizeof(out.dst));
    inet_ntop(AF_INET, &ip->ip_src, out.src, sizeof(out.src));
    inet_ntop(AF_INET, &ip->ip_dst, out.dst, sizeof(out.dst));

    return true;
}

size_t get_flow_key_hash(const PayloadInfo& pi)
{
    return FlowKeyHash{}(pi);
}