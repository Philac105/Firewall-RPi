#pragma once

#include <cstddef>
#include <cstdint>

struct FlowKey {
    // IP protocol (TCP/UDP/etc.) used for flow identity.
    std::uint8_t protocol = 0;
    // Source L4 port.
    std::uint16_t src_port = 0;
    // Destination L4 port.
    std::uint16_t dst_port = 0;
    // Source IPv4 address packed in host integer form.
    std::uint32_t src_ip = 0;
    // Destination IPv4 address packed in host integer form.
    std::uint32_t dst_ip = 0;

    bool operator==(const FlowKey &other) const noexcept {
        return protocol == other.protocol
               && src_port == other.src_port
               && dst_port == other.dst_port
               && src_ip == other.src_ip
               && dst_ip == other.dst_ip;
    }
};

struct FlowKeyHash {
    // Hash function for unordered containers keyed by FlowKey.
    std::size_t operator()(const FlowKey &key) const noexcept {
        std::size_t h = static_cast<std::size_t>(key.protocol);
        h = h * 1315423911u + static_cast<std::size_t>(key.src_port);
        h = h * 1315423911u + static_cast<std::size_t>(key.dst_port);
        h = h * 1315423911u + static_cast<std::size_t>(key.src_ip);
        h = h * 1315423911u + static_cast<std::size_t>(key.dst_ip);
        return h;
    }
};
