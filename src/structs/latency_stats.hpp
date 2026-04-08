#pragma once

#include <limits>
#include <cstdint>

struct LatencyStats {
    // Number of packets measured in the current report window.
    std::uint64_t count = 0;
    // Sum of per-packet latency values (ns) for average calculation.
    std::uint64_t total_ns = 0;
    // Smallest and largest observed processing times (ns).
    std::uint64_t min_ns = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t max_ns = 0;
    // Packets that exceeded the WCET threshold.
    std::uint64_t wcet_violations = 0;

    void record(std::uint64_t elapsed_ns, std::uint64_t wcet_threshold_ns) noexcept {
        ++count;
        total_ns += elapsed_ns;
        if (elapsed_ns < min_ns) min_ns = elapsed_ns;
        if (elapsed_ns > max_ns) max_ns = elapsed_ns;
        if (elapsed_ns > wcet_threshold_ns) ++wcet_violations;
    }

    void reset() noexcept {
        count = 0;
        total_ns = 0;
        min_ns = std::numeric_limits<std::uint64_t>::max();
        max_ns = 0;
        wcet_violations = 0;
    }
};