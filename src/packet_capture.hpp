// Fait par: Xavier Breton (brex1001)
// Dernière modification par: Philippe Lacasse (lacp2116)

#pragma once

#include <string>

#include "structs/packet_capture_config.hpp"
#include "structs/packet_meta.hpp"

class PacketCapture {
public:
    enum class CaptureStatus : unsigned char {
        Ipv4Ready,
        Timeout,
        IgnoredPacket,
        StreamEnded,
        FatalError,
    };

    PacketCapture() = default;

    ~PacketCapture();

    PacketCapture(const PacketCapture &) = delete;

    PacketCapture &operator=(const PacketCapture &) = delete;

    bool open(const PacketCaptureConfig &config, std::string &error_message);

    CaptureStatus capture_one(PacketMeta &packet_meta, std::string &error_message);

    void close() noexcept;

private:
    pcap_t *handle_ = nullptr;
};
