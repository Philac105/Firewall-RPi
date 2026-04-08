#pragma once

#include <cstdint>

struct TokenBucket {
    // Current token balance.
    double tokens = 300.0;
    // Monotonic timestamp (ns) of the last refill.
    std::uint64_t last_refill_ns = 0;
};
