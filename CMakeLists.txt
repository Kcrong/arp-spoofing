cmake_minimum_required(VERSION 3.5)
project(arp_spoofing)

find_package(PCAP REQUIRED)

INCLUDE_DIRECTORIES(${PCAP_INCLUDE_DIR} INCLUDE ${PCAP_LIBRARY})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
SET (CMAKE_EXE_LINKER_FLAGS -lpcap)
set(SOURCE_FILES main.c)
add_executable(arp_spoofing ${SOURCE_FILES})

target_link_libraries(arp_spoofing ${PCAP_LIBRARY})