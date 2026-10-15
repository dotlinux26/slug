#pragma once

#include <cstdint>
#include <mutex>

namespace slug::net {

class AntiReplaySlidingWindow {
public:
    static constexpr uint64_t kWindowSize = 64;

    AntiReplaySlidingWindow() = default;

    // Returns true if the packet sequence number is valid (fresh and not in replay window)
    bool check(uint64_t seq) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (seq == 0) return false;

        if (seq > highest_seq_) {
            return true; // Ahead of window: fresh!
        }

        uint64_t diff = highest_seq_ - seq;
        if (diff >= kWindowSize) {
            return false; // Packet is too old: drop without decrypting!
        }

        // Check if bit is already set (already received)
        return (bitmap_ & (1ULL << diff)) == 0;
    }

    // Updates the window after successful decryption/verification of the packet
    void update(uint64_t seq) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (seq > highest_seq_) {
            uint64_t diff = seq - highest_seq_;
            if (diff >= kWindowSize) {
                bitmap_ = 1ULL;
            } else {
                bitmap_ = (bitmap_ << diff) | 1ULL;
            }
            highest_seq_ = seq;
        } else {
            uint64_t diff = highest_seq_ - seq;
            if (diff < kWindowSize) {
                bitmap_ |= (1ULL << diff);
            }
        }
    }

    uint64_t highest_sequence() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return highest_seq_;
    }

private:
    mutable std::mutex mutex_;
    uint64_t highest_seq_{0};
    uint64_t bitmap_{0};
};

} // namespace slug::net
