#include "http_flow_statistics.hpp"

#include <iostream>
#include <vector>

void HttpFlowStatistics::printSummary(const HttpFlowStore& store)
{
    std::cout << "\n=== HTTP FLOW STATISTICS ===" << std::endl;

    std::cout << "Active flows tracked: " << store.size() << std::endl;
    std::cout << "Completed flows (archived): " << store.completed_count() << std::endl;

    int incomplete_flows = 0;
    int awaiting_response = 0;

    for (const auto& [flow_key, data] : store.map())
    {
        if (data.totalBytes > 0 && data.byteCount < data.totalBytes)
        {
            incomplete_flows++;
            std::cout << "Incomplete flow " << flow_key << ": totalBytes=" << data.totalBytes
                      << " byteCount=" << data.byteCount << " ("
                      << (data.byteCount * 100.0 / data.totalBytes) << "%)" << std::endl;
        }
        else if (data.totalBytes == 0)
        {
            awaiting_response++;
            std::cout << "Flow awaiting HTTP response " << flow_key
                      << ": byteCount=" << data.byteCount
                      << " server_isn_set=" << data.server_isn_set
                      << " buffered=" << data.buffered_packets.size() << std::endl;
        }
    }

    std::cout << "Incomplete flows (started but interrupted): " << incomplete_flows << std::endl;
    std::cout << "Flows awaiting response (request sent, no response): " << awaiting_response
              << std::endl;
    std::cout << "============================" << std::endl;
}

bool HttpFlowStatistics::exportFlows(const HttpFlowStore& store, FlowExporter& exporter,
                                     const std::string& output)
{
    std::cout << "Exporting flows using " << exporter.getFormatName() << " format..." << std::endl;
    return exporter.exportFlows(store, output);
}
