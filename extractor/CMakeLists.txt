cmake_minimum_required(VERSION 3.15)
project(extractor LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Gaseste libpcap
find_path(PCAP_INCLUDE_DIR pcap.h
    HINTS /opt/homebrew/opt/libpcap/include
          /usr/local/opt/libpcap/include
          /usr/include)

find_library(PCAP_LIBRARY pcap
    HINTS /opt/homebrew/opt/libpcap/lib
          /usr/local/opt/libpcap/lib
          /usr/lib)

if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found. Run: brew install libpcap")
endif()

add_executable(extractor
    src/main.c
    src/packet_parser.c
    src/flow_table.c
    src/graph_window.c
    src/csv_writer.c
)

target_include_directories(extractor PRIVATE src ${PCAP_INCLUDE_DIR})
target_link_libraries(extractor PRIVATE ${PCAP_LIBRARY} m)

# -Wall pentru warnings
target_compile_options(extractor PRIVATE -Wall -Wextra)