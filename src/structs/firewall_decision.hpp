#pragma once

#include <cstdint>

// Common pass/drop outcome used by policy and app-level fail-safe logic.
enum class FirewallDecision : std::uint8_t {
    Pass,
    Drop,
};
