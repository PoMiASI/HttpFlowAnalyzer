#include <cstring>
#include <iostream>
#include <memory>
#include <string>

#include "http_flow_sniffer_app.hpp"

static void usage(const char* prog)
{
    std::cerr << "Usage: " << prog << " -i <interface> [-f <filter>] [-o <output.csv>]\n";
    std::cerr << "  -i <interface>   Network interface to capture on (required)\n";
    std::cerr << "  -f <filter>      BPF filter (default: \"tcp port 80\")\n";
    std::cerr << "  -o <output.csv>  Export flow statistics to CSV file (optional)\n";
}

int main(int argc, char** argv)
{
    const char* dev = nullptr;
    const char* filter_expr = "tcp port 80";
    const char* csv_output = nullptr;

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

    HttpFlowSnifferApp app(dev, filter_expr, csv_output ? csv_output : "");
    app.run();

    return 0;
}
