#include "logger.hpp"

#include <chrono>
#include <cstdio>

AsyncLogger::~AsyncLogger() {
    stop();
}

void AsyncLogger::start() {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }

    worker_ = std::thread(&AsyncLogger::worker_loop, this);
}

void AsyncLogger::stop() {
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
        return;
    }

    if (worker_.joinable()) {
        worker_.join();
    }
}

void AsyncLogger::log(LogLevel level, std::string_view message) noexcept {
    const std::uint32_t tail = tail_.load(std::memory_order_relaxed);
    const std::uint32_t next = (tail + 1U) % kQueueSize;
    const std::uint32_t head = head_.load(std::memory_order_acquire);

    if (next == head) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    Message& slot = queue_[tail];
    slot.level = level;

    const std::size_t size = message.size() < kMessageMaxLen ? message.size() : kMessageMaxLen;
    slot.len = static_cast<std::uint16_t>(size);
    std::memcpy(slot.text, message.data(), size);
    slot.text[size] = '\0';

    tail_.store(next, std::memory_order_release);
}

std::uint64_t AsyncLogger::dropped_count() const noexcept {
    return dropped_.load(std::memory_order_relaxed);
}

const char* AsyncLogger::level_to_text(const LogLevel level) noexcept {
    switch (level) {
        case LogLevel::Info:
            return "INFO";
        case LogLevel::Warning:
            return "WARN";
        case LogLevel::Error:
            return "ERR";
    }
    return "UNK";
}

void AsyncLogger::worker_loop() {
    while (running_.load(std::memory_order_acquire)
           || head_.load(std::memory_order_acquire) != tail_.load(std::memory_order_acquire)) {
        const std::uint32_t head = head_.load(std::memory_order_relaxed);
        const std::uint32_t tail = tail_.load(std::memory_order_acquire);

        if (head == tail) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }

        const Message& message = queue_[head];
        std::fprintf(stderr, "[%s] %s\n", level_to_text(message.level), message.text);

        head_.store((head + 1U) % kQueueSize, std::memory_order_release);
    }

    const std::uint64_t dropped = dropped_count();
    if (dropped > 0) {
        std::fprintf(stderr, "[WARN] Logger dropped %llu messages\n", static_cast<unsigned long long>(dropped));
    }
}