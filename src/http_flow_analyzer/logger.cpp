#include "logger.hpp"

// Initialize static members
LogLevel Logger::current_level_ = LogLevel::ERROR;
bool Logger::show_timestamp_ = false;
std::mutex Logger::mutex_;
