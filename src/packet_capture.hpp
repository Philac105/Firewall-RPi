#pragma once

#include <pcap.h>

#include <string>
#include <string_view>

struct PacketCaptureConfig {
    // Interface name used by pcap_open_live.
    std::string interface_name;
    // Maximum bytes captured from each packet.
    int snaplen = BUFSIZ;
    // 1 enables promiscuous mode: capture packets seen on the interface,
    // not only packets addressed to this host.
    int promiscuous = 1;
    // Read timeout for pcap_next_ex in milliseconds.
    int timeout_ms = 1000;
};

struct PacketMeta {
    // Captured packet length in bytes; 0 means timeout/no packet.
    unsigned int packet_length;
};

class PacketCapture {
public:
    PacketCapture() = default;

    ~PacketCapture();

    PacketCapture(const PacketCapture &) = delete;

    PacketCapture &operator=(const PacketCapture &) = delete;

    bool open(const PacketCaptureConfig &config, std::string &error_message);

    bool capture_one(PacketMeta &packet_meta, std::string &error_message);

    void close() noexcept;

private:
    pcap_t *handle_ = nullptr;
};