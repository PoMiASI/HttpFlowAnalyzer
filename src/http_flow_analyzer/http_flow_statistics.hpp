#ifndef HTTP_FLOW_STATISTICS_HPP
#define HTTP_FLOW_STATISTICS_HPP

#include <cstdint>
#include <string>
#include <memory>
#include "http_flow_store.hpp"
#include "flow_exporter.hpp"

class HttpFlowStatistics
{
   public:
    HttpFlowStatistics() = default;
    ~HttpFlowStatistics() = default;

    // Generate and print summary statistics from the given flow store
    static void printSummary(const HttpFlowStore& store);

    // Export flow statistics using the provided exporter implementation
    // Returns true on success, false on error
    static bool exportFlows(const HttpFlowStore& store, FlowExporter& exporter, 
                           const std::string& output);
};

#endif  // HTTP_FLOW_STATISTICS_HPP
