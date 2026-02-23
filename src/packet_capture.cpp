#include "packet_capture.hpp"

#include <cstring>

PacketCapture::~PacketCapture() {
    close();
}

bool PacketCapture::open(const PacketCaptureConfig& config, std::string& error_message) {
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

bool PacketCapture::capture_one(PacketMeta& packet_meta, std::string& error_message) {
    if (!handle_) {
        error_message = "capture handle not initialized";
        return false;
    }

    pcap_pkthdr* header = nullptr;
    const u_char* data = nullptr;
    const int result = pcap_next_ex(handle_, &header, &data);
    (void)data;

    if (result > 0 && header) {
        packet_meta.packet_length = header->len;
        return true;
    }

    if (result == 0) {
        return true;
    }

    if (result == -1) {
        error_message = pcap_geterr(handle_);
        return false;
    }

    if (result == -2) {
        error_message = "pcap stream ended";
        return false;
    }

    error_message = "unknown pcap error";
    return false;
}

void PacketCapture::close() noexcept {
    if (!handle_) {
        return;
    }

    pcap_close(handle_);
    handle_ = nullptr;
}