#pragma once

#include <pcap.h>

#include <string>

struct PacketCaptureConfig {
    // Interface name used by pcap_open_live.
    std::string interface_name;
    // Maximum bytes captured from each packet.
    int snaplen = BUFSIZ;
    // 1 enables promiscuous mode. This captures packets seen on the interface,
    // not only packets addressed to this host.
    int promiscuous = 1;
    // Read timeout for pcap_next_ex in milliseconds.
    int timeout_ms = 1000;
};
