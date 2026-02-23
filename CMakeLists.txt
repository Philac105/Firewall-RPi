cmake_minimum_required(VERSION 4.1)
project(Firewall_RPi)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(Firewall_RPi
        main.cpp
        src/logger.cpp
        src/cpu_affinity.cpp
        src/packet_capture.cpp
        src/firewall_app.cpp
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

target_include_directories(Firewall_RPi PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(Firewall_RPi PRIVATE ${PCAP_LIBRARIES})

add_custom_command(TARGET Firewall_RPi POST_BUILD
        COMMAND sudo setcap cap_net_raw,cap_net_admin=eip $<TARGET_FILE:Firewall_RPi>
        COMMENT "Setting packet capture capabilities on Firewall_RPi"
)