#pragma once

#include <cstdint>

struct ACLRule {
    // Ordered ACL rule identifier (e.g., 2..999, 1000 default deny).
    std::uint32_t id = 0;
    // L4 protocol number (0 means wildcard).
    std::uint8_t protocol = 0;
    // Destination port to match (0 means wildcard).
    std::uint16_t dst_port = 0;
    // True to pass matching packets, false to drop.
    bool allow = true;
    // Human-readable rule label for logging/debug.
    const char *name = "";
};
