#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <thread>

enum class LogLevel : std::uint8_t {
    Info,
    Warning,
    Error,
};

class AsyncLogger {
public:
    AsyncLogger() = default;

    ~AsyncLogger();

    AsyncLogger(const AsyncLogger &) = delete;

    AsyncLogger &operator=(const AsyncLogger &) = delete;

    void start();

    void stop();

    void log(LogLevel level, std::string_view message) noexcept;

    std::uint64_t dropped_count() const noexcept;

private:
    static constexpr std::size_t kQueueSize = 1024;
    static constexpr std::size_t kMessageMaxLen = 120;

    struct Message {
        LogLevel level;
        // Actual message length stored in text (excluding null terminator).
        std::uint16_t len;
        // Fixed-size payload buffer used by the ring queue.
        char text[kMessageMaxLen + 1];
    };

    void worker_loop();

    static const char *level_to_text(LogLevel level) noexcept;

    alignas(64) std::array<Message, kQueueSize> queue_{};
    alignas(64) std::atomic<std::uint32_t> head_{0};
    alignas(64) std::atomic<std::uint32_t> tail_{0};

    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> dropped_{0};
    std::thread worker_;
};