#include "http_flow_sniffer_app.hpp"

#include <iostream>

#include "csv_flow_exporter.hpp"
#include "http_flow_statistics.hpp"
#include "signal_registry.hpp"

HttpFlowSnifferApp::HttpFlowSnifferApp(const std::string& interface, const std::string& filter,
                                       const std::string& csv_output)
    : interface_(interface), filter_(filter), csv_output_(csv_output), capture_engine_(interface)
{
    // Disable stdout buffering for real-time output when redirected to file
    std::cout.setf(std::ios::unitbuf);
    capture_engine_.addFilter(filter_);
}

HttpFlowSnifferApp::~HttpFlowSnifferApp() = default;

void HttpFlowSnifferApp::run()
{
    // Register this instance for signal handling
    SignalRegistry<HttpFlowSnifferApp>::registerInstance(this);

    capture_engine_.run(analyzer_, &stop_flag_);

    // Unregister signal handlers and print final statistics
    SignalRegistry<HttpFlowSnifferApp>::unregisterInstance();
    analyzer_.printStatistics();

    // Export to CSV if output file specified
    if (!csv_output_.empty())
    {
        CSVFlowExporter csv_exporter;
        HttpFlowStatistics::exportFlows(analyzer_.getFlowStore(), csv_exporter, csv_output_);
    }
}

void HttpFlowSnifferApp::stop()
{
    stop_flag_.store(true, std::memory_order_release);
}
