#pragma once

#include <cstdint>
#include <string_view>

#include "firewall_policy.hpp"
#include "logger.hpp"
#include "packet_capture.hpp"
#include "structs/firewall_decision.hpp"

class FirewallApp {
public:
    explicit FirewallApp(AsyncLogger &logger);

    bool initialize(int cpu_core, std::string_view interface_name);

    void run();

    static constexpr std::uint64_t kWcetThresholdNs = 1'000'000;

private:
    static constexpr int kRealtimePriority = 90;

    FirewallDecision process_packet(const PacketMeta& packet) noexcept;
    void report_rule_hits() noexcept;

    AsyncLogger &logger_;
    PacketCapture capture_;
    FirewallPolicy policy_;
    bool running_ = false;
};