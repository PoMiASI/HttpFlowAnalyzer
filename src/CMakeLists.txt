add_executable(http_flow_analyzer
	${CMAKE_CURRENT_SOURCE_DIR}/http_flow_analyzer/main.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/http_flow_analyzer/http_flow_sniffer_app.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/http_flow_analyzer/http_flow_analyzer.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/http_flow_analyzer/sniffer_utils.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/http_flow_analyzer/capture_engine.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/http_flow_analyzer/http_flow_statistics.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/http_flow_analyzer/csv_flow_exporter.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/http_flow_analyzer/logger.cpp
)

target_compile_options(http_flow_analyzer PRIVATE -O2 -Wall)
target_include_directories(http_flow_analyzer PRIVATE ${PCAP_INCLUDE_DIRS} ${PICOHTTPPARSER_DIR} http_flow_analyzer)
target_link_libraries(http_flow_analyzer ${PCAP_LIBRARIES} picohttpparser_lib)

# Install target (optional)
install(TARGETS http_flow_analyzer RUNTIME DESTINATION bin)
