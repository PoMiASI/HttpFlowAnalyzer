#ifndef CSV_FLOW_EXPORTER_HPP
#define CSV_FLOW_EXPORTER_HPP

#include "flow_exporter.hpp"

// Concrete implementation: exports HTTP flows to CSV format
class CSVFlowExporter : public FlowExporter
{
   public:
    CSVFlowExporter() = default;
    ~CSVFlowExporter() override = default;

    bool exportFlows(const HttpFlowStore& store, const std::string& output) override;
    const char* getFormatName() const override { return "CSV"; }
};

#endif  // CSV_FLOW_EXPORTER_HPP
