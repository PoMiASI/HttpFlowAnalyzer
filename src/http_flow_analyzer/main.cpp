#include <cstring>
#include <iostream>
#include <memory>
#include <string>

#include "http_flow_sniffer_app.hpp"
#include "logger.hpp"

static void usage(const char* prog)
{
    std::cerr << "Usage: " << prog << " -i <interface> [-f <filter>] [-o <output.csv>] [-v <level>] [--quiet]\n";
    std::cerr << "  -i <interface>   Network interface to capture on (required)\n";
    std::cerr << "  -f <filter>      BPF filter (default: \"tcp port 80\")\n";
    std::cerr << "  -o <output.csv>  Export flow statistics to CSV file (optional)\n";
    std::cerr << "  -v <level>       Log level: 0=DEBUG, 1=INFO, 2=WARNING, 3=ERROR (default: 2)\n";
    std::cerr << "  --quiet          Disable all logging\n";
    std::cerr << "  --timestamp      Show timestamps in logs\n";
}

int main(int argc, char** argv)
{
    const char* dev = nullptr;
    const char* filter_expr = "tcp port 80";
    const char* csv_output = nullptr;
    LogLevel log_level = LogLevel::ERROR;  // Default
    bool show_timestamp = false;

    if (argc == 1)
    {
        usage(argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; ++i)
    {
        if (std::strcmp(argv[i], "-i") == 0 && i + 1 < argc)
        {
            dev = argv[++i];
        }
        else if (std::strcmp(argv[i], "-f") == 0 && i + 1 < argc)
        {
            filter_expr = argv[++i];
        }
        else if (std::strcmp(argv[i], "-o") == 0 && i + 1 < argc)
        {
            csv_output = argv[++i];
        }
        else if (std::strcmp(argv[i], "-v") == 0 && i + 1 < argc)
        {
            int level = std::atoi(argv[++i]);
            if (level >= 0 && level <= 3)
            {
                log_level = static_cast<LogLevel>(level);
            }
            else
            {
                std::cerr << "Invalid log level. Use 0-3.\n";
                return 1;
            }
        }
        else if (std::strcmp(argv[i], "--quiet") == 0)
        {
            log_level = LogLevel::NONE;
        }
        else if (std::strcmp(argv[i], "--timestamp") == 0)
        {
            show_timestamp = true;
        }
        else
        {
            usage(argv[0]);
            return 1;
        }
    }

    if (dev == nullptr)
    {
        std::cerr << "Interface not specified.\n";
        usage(argv[0]);
        return 1;
    }

    if (csv_output == nullptr)
    {
        csv_output = "output.csv";
    }

    // Configure logger
    Logger::setLevel(log_level);
    Logger::setShowTimestamp(show_timestamp);
    
    LOG_INFO("HTTP Flow Analyzer starting...");
    LOG_INFO("Interface: " << dev);
    LOG_INFO("Filter: " << filter_expr);
    LOG_INFO("Output: " << csv_output);
    LOG_DEBUG("Log level: " << static_cast<int>(log_level));

    HttpFlowSnifferApp app(dev, filter_expr, csv_output);
    app.run();

    LOG_INFO("HTTP Flow Analyzer stopped");

    return 0;
}
