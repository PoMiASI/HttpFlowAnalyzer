cmake_minimum_required(VERSION 3.5)
project(HttpFlowAnalyzer VERSION 1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for clang-tidy
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Optional: Enable clang-tidy during build
# Uncomment to run clang-tidy automatically during compilation
# set(CMAKE_CXX_CLANG_TIDY "clang-tidy;-checks=-*,readability-*,performance-*,bugprone-*")

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/picohttpparser.cmake)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})

add_subdirectory(src)