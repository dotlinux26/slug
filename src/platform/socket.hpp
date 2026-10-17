#pragma once

#include "src/platform/platform.hpp"
#include <string>
#include <vector>
#include <span>
#include <chrono>
#include <optional>

namespace slug::platform {

#if defined(SLUG_PLATFORM_WINDOWS)
    using SocketHandle = SOCKET;
    constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
#else
    using SocketHandle = int;
    constexpr SocketHandle kInvalidSocket = -1;
#endif

struct Endpoint {
    std::string ip;
    uint16_t port{0};
};

class SocketUtils {
public:
    static void close_socket(SocketHandle s);
    static bool set_nonblocking(SocketHandle s, bool nonblocking);
    static bool set_reuse_addr(SocketHandle s, bool reuse);
    static bool set_timeouts(SocketHandle s, int timeout_ms);
};

class TcpSocket {
public:
    TcpSocket();
    explicit TcpSocket(SocketHandle s, const Endpoint& peer);
    ~TcpSocket();

    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;
    TcpSocket(TcpSocket&& other) noexcept;
    TcpSocket& operator=(TcpSocket&& other) noexcept;

    bool connect(const std::string& host, uint16_t port, int timeout_ms = 5000);
    bool connect_with_timeout(const std::string& host, uint16_t port, int timeout_ms = 5000) {
        return connect(host, port, timeout_ms);
    }
    bool send_all(std::span<const uint8_t> data);
    bool send_all(const std::string& str);
    int receive(std::span<uint8_t> buffer, int timeout_ms = -1);
    bool receive_exact(std::span<uint8_t> buffer, int timeout_ms = 5000);

    void close();
    bool is_valid() const { return handle_ != kInvalidSocket; }
    SocketHandle native_handle() const { return handle_; }
    const Endpoint& peer_endpoint() const { return peer_; }

private:
    SocketHandle handle_{kInvalidSocket};
    Endpoint peer_{};
};

class TcpListener {
public:
    TcpListener();
    ~TcpListener();

    TcpListener(const TcpListener&) = delete;
    TcpListener& operator=(const TcpListener&) = delete;
    TcpListener(TcpListener&& other) noexcept;
    TcpListener& operator=(TcpListener&& other) noexcept;

    bool bind_and_listen(const std::string& bind_ip, uint16_t port, int backlog = 32);
    std::optional<TcpSocket> accept(int timeout_ms = -1);

    void close();
    bool is_valid() const { return handle_ != kInvalidSocket; }
    uint16_t bound_port() const { return port_; }

private:
    SocketHandle handle_{kInvalidSocket};
    uint16_t port_{0};
};

class UdpSocket {
public:
    UdpSocket();
    ~UdpSocket();

    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;
    UdpSocket(UdpSocket&& other) noexcept;
    UdpSocket& operator=(UdpSocket&& other) noexcept;

    bool bind(const std::string& bind_ip, uint16_t port);
    int send_to(std::span<const uint8_t> data, const Endpoint& target);
    int receive_from(std::span<uint8_t> buffer, Endpoint& sender, int timeout_ms = -1);

    void close();
    bool is_valid() const { return handle_ != kInvalidSocket; }
    uint16_t bound_port() const { return port_; }

private:
    SocketHandle handle_{kInvalidSocket};
    uint16_t port_{0};
};

} // namespace slug::platform
