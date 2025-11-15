#include "http_flow_sniffer_app.hpp"

#include "csv_flow_exporter.hpp"
#include "http_flow_statistics.hpp"
#include "logger.hpp"
#include "signal_registry.hpp"

HttpFlowSnifferApp::HttpFlowSnifferApp(const std::string& interface, const std::string& filter,
                                       const std::string& csv_output)
    : interface_(interface), 
      filter_(filter), 
      csv_output_(csv_output), 
      capture_engine_(interface)
{
    capture_engine_.addFilter(filter_);
}

HttpFlowSnifferApp::~HttpFlowSnifferApp() = default;

void HttpFlowSnifferApp::run()
{
    // Get server port from capture_engine (extracted from filter)
    uint16_t server_port = capture_engine_.getFilterPort();
    if (server_port == 0)
    {
        LOG_ERROR("Could not extract server port from filter: '" << filter_ << "'");
        LOG_ERROR("Filter must contain 'port NNNN' pattern (e.g., 'tcp port 8080')");
        return;
    }
    
    LOG_INFO("Server port extracted from filter: " << server_port);
    analyzer_.setServerPort(server_port);
    
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
    capture_engine_.stop();
}
