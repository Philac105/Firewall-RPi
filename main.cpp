#include <iostream>
#include <string>
#include <string_view>

#include "src/firewall_app.hpp"
#include "src/logger.hpp"


struct CliConfig {
    int cpu_core = 3;
    std::string interface_name = "wlan0";
};

bool parse_int(const std::string& value, int& output) {
    try {
        output = std::stoi(value);
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_cli(const int argc, char** argv, CliConfig& config) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "--iface" && i + 1 < argc) {
            config.interface_name = argv[++i];
            continue;
        }

        if (arg == "--cpu" && i + 1 < argc) {
            int cpu = 0;
            if (!parse_int(argv[++i], cpu) || cpu < 0) {
                return false;
            }
            config.cpu_core = cpu;
            continue;
        }

        if (arg == "--help") {
            return false;
        }

        return false;
    }

    return true;
}

int main(int argc, char** argv) {
    CliConfig config;
    if (!parse_cli(argc, argv, config)) {
        std::cerr << "Usage: Firewall_RPi [--iface <name>] [--cpu <index>]" << std::endl;
        return 1;
    }

    AsyncLogger logger;
    logger.start();

    FirewallApp app(logger);
    if (!app.initialize(config.cpu_core, config.interface_name)) {
        logger.log(LogLevel::Error, "Initialization failed");
        logger.stop();
        return 1;
    }

    app.run();
    logger.stop();
    std::cout << "Firewall stopped cleanly" << std::endl;
    return 0;
}
