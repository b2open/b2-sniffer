cmake_minimum_required(VERSION 3.16)

# Set the project name
project (b2-sniffer)

# Set the C++ standard C++11
set(CMAKE_CXX_STANDARD 11)

# Lib PCAP
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" ${CMAKE_MODULE_PATH})
set(PCAP_DIR "${CMAKE_CURRENT_LIST_DIR}")
find_package(PCAP)

# If Capture from PCAP Files, VelodyneCapture are required PCAP.
# Please Define HAVE_PCAP in Preprocessor.
set(HAVE_PCAP)
if(PCAP_FOUND)
  set(HAVE_PCAP "-DHAVE_PCAP")
endif()

# Lib fmt
add_subdirectory(3rdparty/fmt)

# Add an executable
add_executable(b2-sniffer main.cpp)

# Set the C++ standard to the appropriate standard for using auto
target_compile_features(b2-sniffer PUBLIC cxx_auto_type)

# Link Libraries
target_link_libraries(b2-sniffer ${PCAP_LIBRARIES} fmt::fmt)

# Print Compile Features
message("List of compile features: ${CMAKE_CXX_COMPILE_FEATURES}")

# Install
install(TARGETS b2-sniffer DESTINATION bin)
