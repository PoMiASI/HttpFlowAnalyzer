#include "capture_engine.hpp"

#include <assert.h>

#include <atomic>
#include <cctype>
#include <iostream>

#include "logger.hpp"

constexpr auto PCAP_BUFFER_SIZE = 128 * 1024 * 1024; // 128MB
constexpr auto PCAP_TIMEOUT = 1000; // 1 second
constexpr auto PCAP_SNAPLEN = 262144; // 262144 bytes

// User data structure for pcap callback
struct CallbackData
{
    HttpFlowAnalyzer* analyzer;
    std::atomic<bool>* stop_flag;
    pcap_t* handle;
};

extern "C" void pkt_handler(u_char* user, const struct pcap_pkthdr* hdr, const u_char* bytes)
{
    CallbackData* data = reinterpret_cast<CallbackData*>(user);

    // Check if we should stop
    if (data->stop_flag != nullptr && data->stop_flag->load(std::memory_order_acquire))
    {
        pcap_breakloop(data->handle);
        return;
    }

    data->analyzer->onPacketReceived(hdr, bytes);
}

CaptureEngine::CaptureEngine(const std::string& interface) : m_handle(nullptr)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    m_handle = pcap_create(interface.c_str(), errbuf);
    if (m_handle == nullptr)
    {
        throw std::runtime_error(std::string("pcap_create failed: ") + errbuf);
    }

    // Set snaplen - 262144 bytes to avoid truncation
    if (pcap_set_snaplen(m_handle, PCAP_SNAPLEN) != 0)
    {
        pcap_close(m_handle);
        throw std::runtime_error("Failed to set snaplen");
    }

    if (pcap_set_promisc(m_handle, 1) != 0)
    {
        pcap_close(m_handle);
        throw std::runtime_error("Failed to set promisc mode");
    }

    if (pcap_set_timeout(m_handle, PCAP_TIMEOUT) != 0)
    {
        pcap_close(m_handle);
        throw std::runtime_error("Failed to set timeout");
    }

    // CRITICAL: Set large buffer size BEFORE activation (128MB for high-throughput loopback)
    if (pcap_set_buffer_size(m_handle, PCAP_BUFFER_SIZE) != 0)
    {
        pcap_close(m_handle);
        throw std::runtime_error("Failed to set buffer size");
    }

    int status = pcap_activate(m_handle);
    if (status != 0)
    {
        std::string error = "pcap_activate failed: ";
        if (status == PCAP_WARNING)
        {
            LOG_WARNING("pcap_activate warning: " << pcap_geterr(m_handle));
        }
        else
        {
            error += pcap_geterr(m_handle);
            pcap_close(m_handle);
            throw std::runtime_error(error);
        }
    }

    LOG_INFO("Capture initialized with 128MB buffer, snaplen=262144");
}

CaptureEngine::~CaptureEngine()
{
    if (m_handle != nullptr)
    {
        pcap_close(m_handle);
    }
}

uint16_t CaptureEngine::extractPortFromFilter(const std::string& filter)
{
    // Look for patterns like "port 8080" or "port 80"
    size_t port_pos = filter.find("port");
    if (port_pos == std::string::npos)
    {
        return 0; // Not found
    }
    
    // Skip "port" and any whitespace
    size_t num_start = port_pos + 4;
    while (num_start < filter.length() && std::isspace(filter[num_start]))
    {
        ++num_start;
    }
    
    // Extract digits
    if (num_start >= filter.length() || !std::isdigit(filter[num_start]))
    {
        return 0;
    }
    
    size_t num_end = num_start;
    while (num_end < filter.length() && std::isdigit(filter[num_end]))
    {
        ++num_end;
    }
    
    std::string port_str = filter.substr(num_start, num_end - num_start);
    try
    {
        int port = std::stoi(port_str);
        if (port > 0 && port <= 65535)
        {
            return static_cast<uint16_t>(port);
        }
    }
    catch (...)
    {
        return 0;
    }
    
    return 0;
}

bool CaptureEngine::addFilter(const std::string& filter)
{
    assert(m_handle);
    if (m_handle == nullptr)
    {
        return false;
    }

    // Extract port from filter for later use
    m_filter_port = extractPortFromFilter(filter);
    
    struct bpf_program bfp;
    if (pcap_compile(m_handle, &bfp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        LOG_ERROR("pcap_compile failed: " << pcap_geterr(m_handle));
        return false;
    }

    if (pcap_setfilter(m_handle, &bfp) == -1)
    {
        LOG_ERROR("pcap_setfilter failed: " << pcap_geterr(m_handle));
        pcap_freecode(&bfp);
        return false;
    }
    // No longer needed we can free it
    pcap_freecode(&bfp);
    return true;
}

void CaptureEngine::run(HttpFlowAnalyzer& analyzer, std::atomic<bool>* stop_flag)
{
    CallbackData data;
    data.analyzer = &analyzer;
    data.stop_flag = stop_flag;
    data.handle = m_handle;

    // Use pcap_loop with breakloop capability for signal handling
    int result = pcap_loop(m_handle, -1, pkt_handler, reinterpret_cast<u_char*>(&data));

    if (result == -2)
    {
        LOG_INFO("Capture loop terminated by breakloop");
    }
    else if (result == -1)
    {
        LOG_ERROR("Error in pcap_loop: " << pcap_geterr(m_handle));
    }

    struct pcap_stat stats;
    if (pcap_stats(m_handle, &stats) == 0)
    {
        LOG_INFO("=== PCAP STATISTICS ===");
        LOG_INFO("Packets received by filter: " << stats.ps_recv);
        LOG_INFO("Packets dropped by kernel: " << stats.ps_drop);
        LOG_INFO("Packets dropped by interface: " << stats.ps_ifdrop);
        if (stats.ps_drop > 0)
        {
            LOG_WARNING("WARNING: " << stats.ps_drop << " packets were DROPPED!");
            LOG_WARNING("Consider increasing buffer size or processing packets faster.");
        }
        LOG_INFO("=======================");
    }
}

void CaptureEngine::stop()
{
    if (m_handle != nullptr)
    {
        pcap_breakloop(m_handle);
    }
}
