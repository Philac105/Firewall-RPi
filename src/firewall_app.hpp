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
    enum class PacketDecision : unsigned char {
        Pass,
        Drop,
    };

    struct LatencyStats {
        std::uint64_t count = 0;
        std::uint64_t total_ns = 0;
        std::uint64_t min_ns = std::numeric_limits<std::uint64_t>::max();
        std::uint64_t max_ns = 0;
        std::uint64_t wcet_violations = 0;

        void record(std::uint64_t elapsed_ns) noexcept {
            ++count;
            total_ns += elapsed_ns;
            if (elapsed_ns < min_ns) min_ns = elapsed_ns;
            if (elapsed_ns > max_ns) max_ns = elapsed_ns;
            if (elapsed_ns > 1'000'000ULL) ++wcet_violations;
        }

        void reset() noexcept {
            count = 0;
            total_ns = 0;
            min_ns = std::numeric_limits<std::uint64_t>::max();
            max_ns = 0;
            wcet_violations = 0;
        }
    };

    static constexpr int kRealtimePriority = 90;
    static constexpr std::uint64_t kWcetThresholdNs = 1'000'000;

    PacketDecision process_packet(const PacketMeta &packet) noexcept;

    AsyncLogger &logger_;
    PacketCapture capture_;
    bool running_ = false;
};