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

// Option A: TCP Binary Streaming Protocol
// Binary frames are encapsulated directly inside Post-Quantum AEAD frames without Base64/JSON overhead.
enum class StreamFrameType : uint8_t {
    DATA          = 0x01, // Binary payload frame carrying offset + raw bytes
    END_OF_STREAM = 0x02, // End of file/range transmission, carrying expected 32B BLAKE3 hash
    ABORT         = 0x03  // Abort/error signal from peer
};

struct StreamDataFrameHeader {
    uint8_t  magic{0x53};         // 'S' (Slug Stream)
    uint8_t  frame_type{static_cast<uint8_t>(StreamFrameType::DATA)};
    uint16_t reserved{0};
    uint32_t transfer_id{0};
    uint64_t offset{0};
    uint32_t payload_len{0};
};
#pragma pack(pop)

static_assert(sizeof(UdpPacketHeader) == 24, "UdpPacketHeader must be exactly 24 bytes");
static_assert(sizeof(StreamDataFrameHeader) == 20, "StreamDataFrameHeader must be exactly 20 bytes");

// High throughput bounded chunk size for bulk AEAD binary streaming (512 KiB)
constexpr size_t kStreamPayloadChunkSize = 512 * 1024;

} // namespace slug::net

