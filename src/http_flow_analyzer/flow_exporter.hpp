#ifndef FLOW_EXPORTER_HPP
#define FLOW_EXPORTER_HPP

#include <string>
#include "http_flow_store.hpp"

// Abstract interface for exporting HTTP flow statistics to various formats
class FlowExporter
{
   public:
    virtual ~FlowExporter() = default;

    // Export flow data to the specified output destination
    // Returns true on success, false on error
    virtual bool exportFlows(const HttpFlowStore& store, const std::string& output) = 0;

    // Get the format name (e.g., "CSV", "JSON", "XML")
    virtual const char* getFormatName() const = 0;
};

#endif  // FLOW_EXPORTER_HPP
