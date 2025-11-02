# HttpFlowAnalyzer

Lightweight libpcap-based sniffer for HTTP traffic (default: TCP port 80). Captures packets and prints a timestamp, `src:port -> dst:port`, and the first HTTP request/response line when present.

## Requirements
- libpcap development headers and build tools:
  sudo apt-get install libpcap-dev build-essential cmake

## Submodules

This repository uses git submodules for external dependencies (for example, `external/picohttpparser`). After cloning the project you should initialize and fetch submodules so the external libraries are available.

If you've already cloned, run:

```bash
git submodule update --init --recursive
```

## Build
Run from the project root:
```bash
cmake -S . -B build
cmake --build build
```
The resulting binary is `build/pcap_sniffer`.

## Run
Requires privileges to capture packets (root or appropriate capabilities):
```bash
sudo ./build/pcap_sniffer -i <interface>
# or grant capabilities and run without sudo:
# sudo setcap cap_net_raw,cap_net_admin+ep ./build/pcap_sniffer
```

## Usage
```
-i <interface>    Interface to capture on (required)
-f <filter>       BPF filter (default: "tcp port 80")
-c <count>        Stop after <count> packets
```

## Examples
Capture from interface `eth0`:
```bash
sudo ./build/pcap_sniffer -i eth0
```
Capture only traffic matching a custom filter and stop after SIGINT or SIGTERM:
```bash
sudo ./build/pcap_sniffer -i eth0 -f "tcp and host 192.0.2.1"
```

## Output
@TODO Improve this section

Example:
```
```

Notes:
- Default BPF filter is `"tcp port 80"`.
- Capturing encrypted HTTPS (port 443) will not show HTTP request/response lines.
- For long-running captures, consider rotating logs or using an external capture tool.
