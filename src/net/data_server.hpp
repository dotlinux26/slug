#pragma once

#include "src/platform/socket.hpp"
#include "src/net/protocol.hpp"
#include "src/net/sliding_window.hpp"
#include "src/crypto/xchacha20poly1305.hpp"
#include <vector>
#include <thread>
#include <atomic>
#include <memory>
#include <functional>

namespace slug::net {

class DataServer {
public:
    DataServer(uint16_t port);
    ~DataServer();

    bool start();
    void stop();

    uint16_t port() const { return port_; }
    bool is_running() const { return running_; }

    // Send encrypted chunk via UDP
    bool send_chunk(uint32_t session_id, uint32_t transfer_id, uint32_t chunk_idx,
                    std::span<const uint8_t> chunk_data,
                    const std::array<uint8_t, 32>& key,
                    const std::array<uint8_t, 16>& salt,
                    const platform::Endpoint& target);

private:
    uint16_t port_;
    std::atomic<bool> running_{false};
    platform::UdpSocket socket_;
    std::unique_ptr<std::thread> worker_thread_;

    std::atomic<uint64_t> packet_seq_generator_{1};
    AntiReplaySlidingWindow sliding_window_;

    void run_receive_loop();
};

} // namespace slug::net
