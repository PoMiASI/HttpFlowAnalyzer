#ifndef CAPTURE_ENGINE_HPP
#define CAPTURE_ENGINE_HPP

#include <pcap.h>

#include <atomic>
#include <string>

#include "http_flow_analyzer.hpp"

class CaptureEngine
{
   public:
    CaptureEngine(const std::string& interface);
    ~CaptureEngine();

    bool addFilter(const std::string& filter);
    void stop();
    
    // Get the server port extracted from the filter (0 if not found)
    uint16_t getFilterPort() const { return m_filter_port; }

    void run(HttpFlowAnalyzer& analyzer, std::atomic<bool>* stop_flag = nullptr);

   private:
    // Extract port from BPF filter string
    static uint16_t extractPortFromFilter(const std::string& filter);
    
    pcap_t* m_handle;
    uint16_t m_filter_port{0}; // Port extracted from filter
};

#endif  // CAPTURE_ENGINE_HPP
