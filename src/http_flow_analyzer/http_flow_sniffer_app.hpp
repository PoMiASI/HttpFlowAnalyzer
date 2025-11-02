#ifndef HTTP_FLOW_SNIFFER_APP_HPP
#define HTTP_FLOW_SNIFFER_APP_HPP

#include <string>
#include <atomic>
#include "capture_engine.hpp"
#include "http_flow_analyzer.hpp"

class HttpFlowSnifferApp
{
  public:
    HttpFlowSnifferApp(const std::string& interface, const std::string& filter,
                       const std::string& csv_output = "");
    ~HttpFlowSnifferApp();

    void run();
    void stop();

  private:
    std::string interface_;
    std::string filter_;
    std::string csv_output_;
    CaptureEngine capture_engine_;
    HttpFlowAnalyzer analyzer_;
    std::atomic<bool> stop_flag_{false};
};

#endif // HTTP_FLOW_SNIFFER_APP_HPP
