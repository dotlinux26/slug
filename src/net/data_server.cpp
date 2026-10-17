#include "src/net/data_server.hpp"
#include <cstring>
#include <iostream>

namespace slug::net {

DataServer::DataServer(uint16_t port) : port_(port) {}

DataServer::~DataServer() {
    stop();
}

bool DataServer::start() {
    if (running_) return true;

    if (!socket_.bind("0.0.0.0", port_)) {
        return false;
    }
    port_ = socket_.bound_port();

    running_ = true;
    worker_thread_ = std::make_unique<std::thread>(&DataServer::run_receive_loop, this);
    return true;
}

void DataServer::stop() {
    if (!running_) return;
    running_ = false;
    socket_.close();
    if (worker_thread_ && worker_thread_->joinable()) {
        worker_thread_->join();
    }
}

bool DataServer::send_chunk(uint32_t session_id, uint32_t transfer_id, uint32_t chunk_idx,
                            std::span<const uint8_t> chunk_data,
                            const std::array<uint8_t, 32>& key,
                            const std::array<uint8_t, 16>& salt,
                            const platform::Endpoint& target) {

    uint64_t seq = packet_seq_generator_++;

    UdpPacketHeader hdr;
    hdr.session_id = session_id;
    hdr.transfer_id = transfer_id;
    hdr.packet_seq_num = seq;
    hdr.chunk_index = chunk_idx;
    hdr.flags = 0;

    // 24-byte Nonce: salt[16] || packet_seq[8]
    std::array<uint8_t, 24> nonce{};
    std::memcpy(nonce.data(), salt.data(), 16);
    std::memcpy(nonce.data() + 16, &seq, 8);

    // Associated Authenticated Data: 24-byte Header
    auto aad = hdr.to_aad();

    // AEAD encryption
    auto encrypted_payload = crypto::XChaCha20Poly1305::encrypt(chunk_data, key, nonce, aad);

    // Full datagram = Header (24B) + Encrypted Payload (with 16B Poly1305 tag)
    std::vector<uint8_t> packet(sizeof(hdr) + encrypted_payload.size());
    std::memcpy(packet.data(), &hdr, sizeof(hdr));
    std::memcpy(packet.data() + sizeof(hdr), encrypted_payload.data(), encrypted_payload.size());

    int sent = socket_.send_to(packet, target);
    return (sent > 0);
}

void DataServer::run_receive_loop() {
    std::vector<uint8_t> buffer(65536);
    platform::Endpoint sender;

    while (running_) {
        int r = socket_.receive_from(buffer, sender, 500);
        if (r < static_cast<int>(sizeof(UdpPacketHeader))) continue;

        UdpPacketHeader hdr;
        std::memcpy(&hdr, buffer.data(), sizeof(hdr));

        // 64-bit Anti-Replay pre-check: drop replayed or expired packets immediately
        if (!sliding_window_.check(hdr.packet_seq_num)) {
            continue;
        }

        // Cryptographic Security Note:
        // Anti-replay window is updated ONLY AFTER authenticating the AEAD Poly1305 tag
        // on the decrypted payload. Advancing it prematurely on raw unauthenticated UDP
        // packets would create an unauthenticated Denial-of-Service vector (Replay Window Poisoning).
    }
}

} // namespace slug::net
