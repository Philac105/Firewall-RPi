#include "firewall_app.hpp"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <string>

#include "cpu_affinity.hpp"

static void format_timestamp(char *buffer, const std::size_t buffer_size) {
    const std::time_t now = std::time(nullptr);
    std::tm local_tm{};
    localtime_r(&now, &local_tm);
    std::strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", &local_tm);
}

FirewallApp::FirewallApp(AsyncLogger &logger) : logger_(logger), policy_() {}

FirewallDecision FirewallApp::process_packet(const PacketMeta &packet) noexcept {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    const std::uint64_t now_ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
    
    const FirewallDecision decision = policy_.evaluate(packet, now_ns);
    return decision;
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
    auto next_report = clock::now() + std::chrono::seconds(kReportIntervalSeconds);
    std::uint64_t interval_passed = 0;
    std::uint64_t interval_dropped = 0;
    std::uint64_t interval_ignored = 0;
    std::uint64_t interval_timeouts = 0;
    LatencyStats latency{};

    while (running_) {
        const PacketCapture::CaptureStatus status = capture_.capture_one(packet, error);
        switch (status) {
            case PacketCapture::CaptureStatus::FatalError: {
                std::string message = "Capture failed: ";
                message += error;
                logger_.log(LogLevel::Error, message);
                running_ = false;
                continue;
            }

            case PacketCapture::CaptureStatus::StreamEnded:
                logger_.log(LogLevel::Info, "Capture stream ended");
                running_ = false;
                continue;

            case PacketCapture::CaptureStatus::Ipv4Ready: {
                const auto t0 = clock::now();
                FirewallDecision decision = process_packet(packet);
                const auto t1 = clock::now();

                const auto elapsed_ns = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());

                if (elapsed_ns > kWcetThresholdNs) {
                    decision = FirewallDecision::Drop;
                    logger_.log(LogLevel::Warning, "WCET exceeded - packet dropped (fail-safe)");
                }

                latency.record(elapsed_ns, kWcetThresholdNs);

                if (decision == FirewallDecision::Pass) {
                    ++interval_passed;
                } else {
                    ++interval_dropped;
                }
                packet.packet_length = 0;
                break;
            }

            case PacketCapture::CaptureStatus::IgnoredPacket:
                ++interval_ignored;
                break;

            case PacketCapture::CaptureStatus::Timeout:
                ++interval_timeouts;
                break;
        }

        const auto now = clock::now();
        if (now >= next_report) {
            char timestamp[32];
            format_timestamp(timestamp, sizeof(timestamp));
            log_interval_report(
                timestamp,
                interval_passed,
                interval_dropped,
                interval_ignored,
                interval_timeouts,
                latency
            );

            interval_passed = 0;
            interval_dropped = 0;
            interval_ignored = 0;
            interval_timeouts = 0;
            latency.reset();
            next_report = now + std::chrono::seconds(kReportIntervalSeconds);
        }
    }
}

void FirewallApp::log_interval_report(
    const char *timestamp,
    const std::uint64_t interval_passed,
    const std::uint64_t interval_dropped,
    const std::uint64_t interval_ignored,
    const std::uint64_t interval_timeouts,
    const LatencyStats &latency
) noexcept {
    logger_.log(LogLevel::Info, "----------------------------------------");

    char traffic_report[160];
    std::snprintf(
        traffic_report,
        sizeof(traffic_report),
        "ts=%s | traffic pass=%llu drop=%llu ign=%llu tout=%llu",
        timestamp,
        static_cast<unsigned long long>(interval_passed),
        static_cast<unsigned long long>(interval_dropped),
        static_cast<unsigned long long>(interval_ignored),
        static_cast<unsigned long long>(interval_timeouts)
    );

    char latency_report[160];
    if (latency.count > 0) {
        const std::uint64_t avg_ns = latency.total_ns / latency.count;
        std::snprintf(
            latency_report,
            sizeof(latency_report),
            "ts=%s | latency min=%lluns avg=%lluns max=%lluns wcet_viol=%llu",
            timestamp,
            static_cast<unsigned long long>(latency.min_ns),
            static_cast<unsigned long long>(avg_ns),
            static_cast<unsigned long long>(latency.max_ns),
            static_cast<unsigned long long>(latency.wcet_violations)
        );
    } else {
        std::snprintf(
            latency_report,
            sizeof(latency_report),
            "ts=%s | lat no packets",
            timestamp
        );
    }

    logger_.log(LogLevel::Info, traffic_report);
    logger_.log(LogLevel::Info, latency_report);
    report_rule_hits(timestamp);
}

void FirewallApp::report_rule_hits(const char *timestamp) noexcept {
    std::string msg = "ts=";
    msg += timestamp;
    msg += " | ";
    msg += policy_.report_counters();
    logger_.log(LogLevel::Info, msg);
}