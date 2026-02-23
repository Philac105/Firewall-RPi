#pragma once

#include <pcap.h>

#include <string>
#include <string_view>

struct PacketCaptureConfig {
    std::string interface_name;
    int snaplen = BUFSIZ;
    int promiscuous = 1;
    int timeout_ms = 1000;
};

struct PacketMeta {
    unsigned int packet_length;
};

class PacketCapture {
public:
    PacketCapture() = default;
    ~PacketCapture();

    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    bool open(const PacketCaptureConfig& config, std::string& error_message);
    bool capture_one(PacketMeta& packet_meta, std::string& error_message);
    void close() noexcept;

private:
    pcap_t* handle_ = nullptr;
};