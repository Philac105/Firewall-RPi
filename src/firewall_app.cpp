#include "firewall_app.hpp"

#include <chrono>
#include <cstdio>
#include <string>

#include "cpu_affinity.hpp"

FirewallApp::FirewallApp(AsyncLogger& logger) : logger_(logger) {}

FirewallApp::PacketDecision FirewallApp::process_packet(const PacketMeta& packet) noexcept {
    (void)packet;
    return PacketDecision::Pass;
}

bool FirewallApp::initialize(const int cpu_core, std::string_view interface_name) {
    const auto affinity = pin_process_to_cpu(static_cast<std::uint32_t>(cpu_core));
    if (!affinity.ok) {
        logger_.log(LogLevel::Error, "Failed to set CPU affinity");
        return false;
    }

    const auto rt = set_realtime_scheduling(kRealtimePriority);
    if (!rt.ok) {
        logger_.log(LogLevel::Warning, "Failed to set SCHED_FIFO – running without RT scheduling");
    } else {
        char msg[80];
        std::snprintf(msg, sizeof(msg), "SCHED_FIFO activated, priority=%d", kRealtimePriority);
        logger_.log(LogLevel::Info, msg);
    }

    PacketCaptureConfig config;
    config.interface_name = interface_name;

    std::string error;
    if (!capture_.open(config, error)) {
        std::string message = "Failed to open capture interface: ";
        message += error;
        logger_.log(LogLevel::Error, message);
        return false;
    }

    logger_.log(LogLevel::Info, "Firewall initialized");
    running_ = true;
    return true;
}

void FirewallApp::run() {
    std::string error;
    PacketMeta packet{};

    using clock = std::chrono::steady_clock;
    auto next_report = clock::now() + std::chrono::seconds(1);
    std::uint64_t interval_passed = 0;
    std::uint64_t interval_dropped = 0;
    std::uint64_t interval_timeouts = 0;
    LatencyStats latency{};

    while (running_) {
        if (!capture_.capture_one(packet, error)) {
            std::string message = "Capture failed: ";
            message += error;
            logger_.log(LogLevel::Error, message);
            running_ = false;
            continue;
        }

        if (packet.packet_length > 0) {
            const auto t0 = clock::now();
            PacketDecision decision = process_packet(packet);
            const auto t1 = clock::now();

            const auto elapsed_ns = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());

            if (elapsed_ns > kWcetThresholdNs) {
                decision = PacketDecision::Drop;
                logger_.log(LogLevel::Warning, "WCET exceeded - packet dropped (fail-safe)");
            }

            latency.record(elapsed_ns);

            if (decision == PacketDecision::Pass) {
                ++interval_passed;
            } else {
                ++interval_dropped;
            }
            packet.packet_length = 0;
        } else {
            ++interval_timeouts;
        }

        const auto now = clock::now();
        if (now >= next_report) {
            char report[120];
            if (latency.count > 0) {
                const std::uint64_t avg_ns = latency.total_ns / latency.count;
                std::snprintf(
                    report,
                    sizeof(report),
                    "pass=%llu drop=%llu tout=%llu | lat min=%lluns avg=%lluns max=%lluns wcet_viol=%llu",
                    static_cast<unsigned long long>(interval_passed),
                    static_cast<unsigned long long>(interval_dropped),
                    static_cast<unsigned long long>(interval_timeouts),
                    static_cast<unsigned long long>(latency.min_ns),
                    static_cast<unsigned long long>(avg_ns),
                    static_cast<unsigned long long>(latency.max_ns),
                    static_cast<unsigned long long>(latency.wcet_violations)
                );
            } else {
                std::snprintf(
                    report,
                    sizeof(report),
                    "pass=%llu drop=%llu tout=%llu | no packets",
                    static_cast<unsigned long long>(interval_passed),
                    static_cast<unsigned long long>(interval_dropped),
                    static_cast<unsigned long long>(interval_timeouts)
                );
            }
            logger_.log(LogLevel::Info, report);

            interval_passed = 0;
            interval_dropped = 0;
            interval_timeouts = 0;
            latency.reset();
            next_report = now + std::chrono::seconds(1);
        }
    }
}