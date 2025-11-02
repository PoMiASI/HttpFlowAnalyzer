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

    void run(HttpFlowAnalyzer& analyzer, std::atomic<bool>* stop_flag = nullptr);

   private:
    pcap_t* m_handle;
};

#endif  // CAPTURE_ENGINE_HPP
