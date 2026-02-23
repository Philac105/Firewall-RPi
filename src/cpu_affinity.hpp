#pragma once

#include <cstdint>

struct AffinityResult {
    bool ok;
    int error_code;
};

AffinityResult pin_process_to_cpu(std::uint32_t cpu_index) noexcept;