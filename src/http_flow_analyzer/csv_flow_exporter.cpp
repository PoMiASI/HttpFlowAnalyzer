#include "csv_flow_exporter.hpp"

#include <fstream>
#include <iostream>
#include <iomanip>

bool CSVFlowExporter::exportFlows(const HttpFlowStore& store, const std::string& output)
{
    std::ofstream csv(output);
    if (!csv.is_open())
    {
        std::cerr << "Failed to open CSV file for writing: " << output << std::endl;
        return false;
    }

    // Write CSV header
    csv << "flow_key,status,total_bytes,received_bytes,completion_percent,"
        << "first_timestamp_ms,last_timestamp_ms,duration_ms,"
        << "server_isn_set,buffered_packets,tcp_seqs_count,"
        << "request_method,request_uri,request_host,request_user_agent,"
        << "client_addr,client_port,server_addr,server_port,request_timestamp_ms\n";

    // Helper lambda to determine flow status
    auto get_status = [](const Data& data) -> std::string {
        if (data.totalBytes > 0 && data.byteCount >= data.totalBytes)
        {
            return "complete";
        }
        else if (data.totalBytes > 0 && data.byteCount < data.totalBytes)
        {
            return "incomplete";
        }
        else if (data.totalBytes == 0 && data.byteCount > 0)
        {
            return "awaiting_response";
        }
        else
        {
            return "unknown";
        }
    };

    // Export active flows
    for (const auto& [flow_key, data] : store.map())
    {
        double completion_percent = 0.0;
        if (data.totalBytes > 0)
        {
            completion_percent = (data.byteCount * 100.0) / data.totalBytes;
        }

        uint64_t duration_ms = 0;
        if (data.last_timestamp_ms >= data.timestamp_ms)
        {
            duration_ms = data.last_timestamp_ms - data.timestamp_ms;
        }

        csv << flow_key << ","
            << get_status(data) << ","
            << data.totalBytes << ","
            << data.byteCount << ","
            << std::fixed << std::setprecision(2) << completion_percent << ","
            << data.timestamp_ms << ","
            << data.last_timestamp_ms << ","
            << duration_ms << ","
            << (data.server_isn_set ? "true" : "false") << ","
            << data.buffered_packets.size() << ","
            << data.tcp_seqs.size() << ","
            << "\"" << data.request_method << "\","
            << "\"" << data.request_uri << "\","
            << "\"" << data.request_host << "\","
            << "\"" << data.request_user_agent << "\","
            << "\"" << data.client_addr << "\","
            << data.client_port << ","
            << "\"" << data.server_addr << "\","
            << data.server_port << ","
            << data.request_timestamp_ms << "\n";
    }

    // Export completed/archived flows
    size_t completed_index = 0;
    for (const auto& data : store.completed())
    {
        double completion_percent = 0.0;
        if (data.totalBytes > 0)
        {
            completion_percent = (data.byteCount * 100.0) / data.totalBytes;
        }

        uint64_t duration_ms = 0;
        if (data.last_timestamp_ms >= data.timestamp_ms)
        {
            duration_ms = data.last_timestamp_ms - data.timestamp_ms;
        }

        // Use a synthetic key for completed flows (to distinguish from active)
        csv << "completed_" << completed_index++ << ","
            << "archived" << ","
            << data.totalBytes << ","
            << data.byteCount << ","
            << std::fixed << std::setprecision(2) << completion_percent << ","
            << data.timestamp_ms << ","
            << data.last_timestamp_ms << ","
            << duration_ms << ","
            << (data.server_isn_set ? "true" : "false") << ","
            << data.buffered_packets.size() << ","
            << data.tcp_seqs.size() << ","
            << "\"" << data.request_method << "\","
            << "\"" << data.request_uri << "\","
            << "\"" << data.request_host << "\","
            << "\"" << data.request_user_agent << "\","
            << "\"" << data.client_addr << "\","
            << data.client_port << ","
            << "\"" << data.server_addr << "\","
            << data.server_port << ","
            << data.request_timestamp_ms << "\n";
    }

    csv.close();
    std::cout << "CSV export complete: " << output << std::endl;
    std::cout << "  Active flows: " << store.size() << std::endl;
    std::cout << "  Completed flows: " << store.completed_count() << std::endl;
    return true;
}
