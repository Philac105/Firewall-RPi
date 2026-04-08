#include "packet_capture.hpp"

#include <cstring>

static constexpr std::uint16_t kEtherTypeIPv4 = 0x0800;
static constexpr std::uint8_t kProtoTcp = 6;
static constexpr std::uint8_t kProtoUdp = 17;
static constexpr std::size_t kEthernetHeaderLen = 14U;
static constexpr std::size_t kMinIpv4HeaderLen = 20U;
static constexpr std::size_t kIpv4WordSizeBytes = 4U;
static constexpr std::size_t kMinPortHeaderLen = 4U;
static constexpr std::size_t kMinTcpHeaderLenForFlags = 14U;
static constexpr std::size_t kEtherTypeOffset = 12U;
static constexpr std::uint8_t kIpv4VersionShift = 4U;
static constexpr std::uint8_t kIpv4IhlMask = 0x0FU;
static constexpr std::size_t kIpv4ProtocolOffset = 9U;
static constexpr std::size_t kIpv4SrcIpOffset = 12U;
static constexpr std::size_t kIpv4DstIpOffset = 16U;
static constexpr std::size_t kTcpFlagsOffset = 13U;

static std::uint16_t read_be16(const std::uint8_t *ptr) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(ptr[0]) << 8U) | ptr[1]);
}

PacketCapture::~PacketCapture() {
    close();
}

bool PacketCapture::open(const PacketCaptureConfig &config, std::string &error_message) {
    close();

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    handle_ = pcap_open_live(
        config.interface_name.c_str(),
        config.snaplen,
        config.promiscuous,
        config.timeout_ms,
        errbuf
    );

    if (!handle_) {
        error_message = errbuf;
        return false;
    }

    return true;
}

PacketCapture::CaptureStatus PacketCapture::capture_one(PacketMeta &packet_meta, std::string &error_message) {
    if (!handle_) {
        error_message = "capture handle not initialized";
        return CaptureStatus::FatalError;
    }

    packet_meta = PacketMeta{};

    pcap_pkthdr *header = nullptr;
    const u_char *data = nullptr;
    const int result = pcap_next_ex(handle_, &header, &data);
    (void) data;

    if (result > 0 && header) {
        packet_meta.packet_length = header->len;

        if (!data || header->caplen < kEthernetHeaderLen) {
            return CaptureStatus::IgnoredPacket;
        }

        const std::uint16_t ether_type = read_be16(data + kEtherTypeOffset);
        if (ether_type != kEtherTypeIPv4) {
            return CaptureStatus::IgnoredPacket;
        }

        if (header->caplen < kEthernetHeaderLen + kMinIpv4HeaderLen) {
            return CaptureStatus::IgnoredPacket;
        }

        const std::uint8_t *ip = data + kEthernetHeaderLen;
        const std::uint8_t version = static_cast<std::uint8_t>((ip[0] >> kIpv4VersionShift) & kIpv4IhlMask);
        if (version != 4) {
            return CaptureStatus::IgnoredPacket;
        }

        const std::uint8_t ihl_words = static_cast<std::uint8_t>(ip[0] & kIpv4IhlMask);
        const std::size_t ihl_bytes = static_cast<std::size_t>(ihl_words) * kIpv4WordSizeBytes;
        if (ihl_bytes < kMinIpv4HeaderLen || header->caplen < kEthernetHeaderLen + ihl_bytes) {
            return CaptureStatus::IgnoredPacket;
        }

        packet_meta.has_ipv4 = true;
        packet_meta.ip_protocol = ip[kIpv4ProtocolOffset];
        packet_meta.src_ip = {ip[kIpv4SrcIpOffset], ip[kIpv4SrcIpOffset + 1], ip[kIpv4SrcIpOffset + 2], ip[kIpv4SrcIpOffset + 3]};
        packet_meta.dst_ip = {ip[kIpv4DstIpOffset], ip[kIpv4DstIpOffset + 1], ip[kIpv4DstIpOffset + 2], ip[kIpv4DstIpOffset + 3]};

        const std::uint8_t *l4 = ip + ihl_bytes;
        const std::size_t l4_len = header->caplen - (kEthernetHeaderLen + ihl_bytes);
        if ((packet_meta.ip_protocol == kProtoTcp || packet_meta.ip_protocol == kProtoUdp) && l4_len >= kMinPortHeaderLen) {
            packet_meta.src_port = read_be16(l4);
            packet_meta.dst_port = read_be16(l4 + 2);
        }

        if (packet_meta.ip_protocol == kProtoTcp && l4_len >= kMinTcpHeaderLenForFlags) {
            packet_meta.tcp_flags = l4[kTcpFlagsOffset];
        }

        return CaptureStatus::Ipv4Ready;
    }

    if (result == 0) {
        return CaptureStatus::Timeout;
    }

    if (result == -1) {
        error_message = pcap_geterr(handle_);
        return CaptureStatus::FatalError;
    }

    if (result == -2) {
        return CaptureStatus::StreamEnded;
    }

    error_message = "unknown pcap error";
    return CaptureStatus::FatalError;
}

void PacketCapture::close() noexcept {
    if (!handle_) {
        return;
    }

    pcap_close(handle_);
    handle_ = nullptr;
}