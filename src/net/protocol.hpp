#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <span>
#include <array>

namespace slug::net {

enum class MessageType : uint8_t {
    CLIENT_HELLO      = 0x01,
    SERVER_HELLO      = 0x02,
    AUTH_REQUEST      = 0x03,
    AUTH_RESPONSE     = 0x04,
    MANIFEST_REQUEST  = 0x05,
    MANIFEST_RESPONSE = 0x06,
    CHUNK_REQUEST     = 0x07,
    CHUNK_DATA        = 0x08,
    FILE_PUSH_HEADER  = 0x09,
    FILE_PUSH_DATA    = 0x0A,
    FILE_PUSH_DONE    = 0x0B,
    ERROR_RESPONSE    = 0x0C
};

#pragma pack(push, 1)
// UDP Chunk Packet Header (24 bytes) per specification
struct UdpPacketHeader {
    uint32_t session_id{0};
    uint32_t transfer_id{0};
    uint64_t packet_seq_num{0};
    uint32_t chunk_index{0};
    uint32_t flags{0};

    // Serializes header as AAD for XChaCha20-Poly1305
    std::array<uint8_t, 24> to_aad() const {
        std::array<uint8_t, 24> aad{};
        std::memcpy(aad.data(), this, 24);
        return aad;
    }
};
#pragma pack(pop)

static_assert(sizeof(UdpPacketHeader) == 24, "UdpPacketHeader must be exactly 24 bytes");

} // namespace slug::net
