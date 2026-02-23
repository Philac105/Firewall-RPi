#pragma once

#include <cstdint>
#include <limits>
#include <string_view>

#include "logger.hpp"
#include "packet_capture.hpp"

class FirewallApp {
public:
    explicit FirewallApp(AsyncLogger &logger);

    bool initialize(int cpu_core, std::string_view interface_name);

    void run();

private:
    static constexpr int kRealtimePriority = 90;
    static constexpr std::uint64_t kWcetThresholdNs = 1'000'000;

    enum class PacketDecision : unsigned char {
        Pass,
        Drop,
    };

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

        void record(std::uint64_t elapsed_ns) noexcept {
            ++count;
            total_ns += elapsed_ns;
            if (elapsed_ns < min_ns) min_ns = elapsed_ns;
            if (elapsed_ns > max_ns) max_ns = elapsed_ns;
            if (elapsed_ns > FirewallApp::kWcetThresholdNs) ++wcet_violations;
        }

        void reset() noexcept {
            count = 0;
            total_ns = 0;
            min_ns = std::numeric_limits<std::uint64_t>::max();
            max_ns = 0;
            wcet_violations = 0;
        }
    };

<<<<<<< HEAD
    PacketDecision process_packet(const PacketMeta& packet) noexcept;
=======
    static constexpr int kRealtimePriority = 90;
    static constexpr std::uint64_t kWcetThresholdNs = 1'000'000;

    PacketDecision process_packet(const PacketMeta &packet) noexcept;
>>>>>>> 0c842545d28b8c5dbe77b2dcb7a908b26aa5258d

    AsyncLogger &logger_;
    PacketCapture capture_;
    bool running_ = false;
};