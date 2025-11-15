#include "http_flow_statistics.hpp"

#include <iostream>
#include <vector>

#include "logger.hpp"

void HttpFlowStatistics::printSummary(const HttpFlowStore& store)
{
    LOG_INFO("=== HTTP FLOW STATISTICS ===");

    LOG_INFO("Active flows tracked: " << store.size());
    LOG_INFO("Completed flows (archived): " << store.completed_count());

    int incomplete_flows = 0;
    int awaiting_response = 0;

    for (const auto& [flow_key, data] : store.map())
    {
        if (data.totalBytes > 0 && data.byteCount < data.totalBytes)
        {
            incomplete_flows++;
            LOG_WARNING("Incomplete flow " << flow_key << ": totalBytes=" << data.totalBytes
                      << " byteCount=" << data.byteCount << " ("
                      << (data.byteCount * 100.0 / data.totalBytes) << "%)");
        }
        else if (data.totalBytes == 0)
        {
            awaiting_response++;
            LOG_DEBUG("Flow awaiting HTTP response " << flow_key
                      << ": byteCount=" << data.byteCount
                      << " server_isn_set=" << data.server_isn_set
                      << " buffered=" << data.buffered_packets.size());
        }
    }

    LOG_INFO("Incomplete flows (started but interrupted): " << incomplete_flows);
    LOG_INFO("Flows awaiting response (request sent, no response): " << awaiting_response);
    LOG_INFO("============================");
}

bool HttpFlowStatistics::exportFlows(const HttpFlowStore& store, FlowExporter& exporter,
                                     const std::string& output)
{
    LOG_INFO("Exporting flows using " << exporter.getFormatName() << " format...");
    return exporter.exportFlows(store, output);
}
