#pragma once

#include <string_view>

#include "logger.hpp"
#include "packet_capture.hpp"

class FirewallApp {
public:
    explicit FirewallApp(AsyncLogger& logger);

    bool initialize(int cpu_core, std::string_view interface_name);
    void run();

private:
    enum class PacketDecision : unsigned char {
        Pass,
        Drop,
    };

    PacketDecision process_packet(const PacketMeta& packet) noexcept;

    AsyncLogger& logger_;
    PacketCapture capture_;
    bool running_ = false;
};