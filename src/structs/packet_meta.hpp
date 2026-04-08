#pragma once

#include <array>
#include <cstdint>

struct PacketMeta {
    // Captured packet length in bytes; 0 means timeout/no packet.
    unsigned int packet_length = 0;
    // True when IPv4 headers were parsed successfully.
    bool has_ipv4 = false;
    // IP protocol number (6 TCP, 17 UDP, etc.).
    std::uint8_t ip_protocol = 0;
    // Source and destination IPv4 addresses in network-byte-order bytes.
    std::array<std::uint8_t, 4> src_ip{};
    std::array<std::uint8_t, 4> dst_ip{};
    // Source and destination ports, available for TCP/UDP packets.
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    // TCP flags byte, only valid when ip_protocol == 6.
    std::uint8_t tcp_flags = 0;
};
