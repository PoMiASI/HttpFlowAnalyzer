# Find picohttpparser from external submodule
set(PICOHTTPPARSER_DIR ${CMAKE_SOURCE_DIR}/external/picohttpparser)

# Check if submodule exists
if(NOT EXISTS ${PICOHTTPPARSER_DIR}/picohttpparser.c)
    message(FATAL_ERROR "picohttpparser submodule not found. Run: git submodule update --init --recursive")
endif()

# Create library from picohttpparser
add_library(picohttpparser_lib
    ${PICOHTTPPARSER_DIR}/picohttpparser.c
    ${PICOHTTPPARSER_DIR}/picohttpparser.h
)

target_include_directories(picohttpparser_lib PUBLIC
    ${PICOHTTPPARSER_DIR}
)

# Set library properties
set_target_properties(picohttpparser_lib PROPERTIES
    C_STANDARD 99
    POSITION_INDEPENDENT_CODE ON
)
