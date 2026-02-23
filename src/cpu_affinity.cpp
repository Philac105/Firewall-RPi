#include "cpu_affinity.hpp"

#include <cerrno>
#include <sched.h>

AffinityResult pin_process_to_cpu(const std::uint32_t cpu_index) noexcept {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_index, &cpuset);

    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) == -1) {
        return {.ok = false, .error_code = errno};
    }

    return {.ok = true, .error_code = 0};
}

AffinityResult set_realtime_scheduling(const int priority) noexcept {
    struct sched_param param{};
    param.sched_priority = priority;

    if (sched_setscheduler(0, SCHED_FIFO, &param) == -1) {
        return {.ok = false, .error_code = errno};
    }

    return {.ok = true, .error_code = 0};
}