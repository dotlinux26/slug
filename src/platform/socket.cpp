#include "src/platform/socket.hpp"
#include <cstring>
#include <iostream>

namespace slug::platform {

void SocketUtils::close_socket(SocketHandle s) {
    if (s == kInvalidSocket) return;
#if defined(SLUG_PLATFORM_WINDOWS)
    closesocket(s);
#else
    ::close(s);
#endif
}

bool SocketUtils::set_nonblocking(SocketHandle s, bool nonblocking) {
    if (s == kInvalidSocket) return false;
#if defined(SLUG_PLATFORM_WINDOWS)
    u_long mode = nonblocking ? 1 : 0;
    return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) return false;
    flags = nonblocking ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    return fcntl(s, F_SETFL, flags) == 0;
#endif
}

bool SocketUtils::set_reuse_addr(SocketHandle s, bool reuse) {
    if (s == kInvalidSocket) return false;
    int opt = reuse ? 1 : 0;
#if defined(SLUG_PLATFORM_WINDOWS)
    return setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt)) == 0;
#else
    return setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == 0;
#endif
}

bool SocketUtils::set_timeouts(SocketHandle s, int timeout_ms) {
    if (s == kInvalidSocket) return false;
#if defined(SLUG_PLATFORM_WINDOWS)
    DWORD tv = timeout_ms > 0 ? static_cast<DWORD>(timeout_ms) : 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv{};
    if (timeout_ms > 0) {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
    }
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
    return true;
}

// TcpSocket
TcpSocket::TcpSocket() : handle_(kInvalidSocket) {}

TcpSocket::TcpSocket(SocketHandle s, const Endpoint& peer)
    : handle_(s), peer_(peer) {}

TcpSocket::~TcpSocket() {
    close();
}

TcpSocket::TcpSocket(TcpSocket&& other) noexcept
    : handle_(other.handle_), peer_(std::move(other.peer_)) {
    other.handle_ = kInvalidSocket;
}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        peer_ = std::move(other.peer_);
        other.handle_ = kInvalidSocket;
    }
    return *this;
}

void TcpSocket::close() {
    if (handle_ != kInvalidSocket) {
        SocketUtils::close_socket(handle_);
        handle_ = kInvalidSocket;
    }
}

bool TcpSocket::connect(const std::string& host, uint16_t port, int timeout_ms) {
    close();
    initialize_network();

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        return false;
    }

    SocketHandle s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == kInvalidSocket) {
        freeaddrinfo(res);
        return false;
    }

    if (timeout_ms > 0) {
        SocketUtils::set_timeouts(s, timeout_ms);
    }

    if (::connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen)) != 0) {
        SocketUtils::close_socket(s);
        freeaddrinfo(res);
        return false;
    }

    freeaddrinfo(res);
    handle_ = s;
    peer_.ip = host;
    peer_.port = port;
    return true;
}

bool TcpSocket::send_all(std::span<const uint8_t> data) {
    if (handle_ == kInvalidSocket) return false;
    size_t total_sent = 0;
    while (total_sent < data.size()) {
        const char* ptr = reinterpret_cast<const char*>(data.data()) + total_sent;
        size_t remaining = data.size() - total_sent;
#if defined(SLUG_PLATFORM_WINDOWS)
        int sent = ::send(handle_, ptr, static_cast<int>(remaining), 0);
#else
        int sent = ::send(handle_, ptr, remaining, MSG_NOSIGNAL);
#endif
        if (sent <= 0) return false;
        total_sent += static_cast<size_t>(sent);
    }
    return true;
}

bool TcpSocket::send_all(const std::string& str) {
    return send_all(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(str.data()), str.size()));
}

int TcpSocket::receive(std::span<uint8_t> buffer, int timeout_ms) {
    if (handle_ == kInvalidSocket || buffer.empty()) return -1;
    if (timeout_ms >= 0) {
        SocketUtils::set_timeouts(handle_, timeout_ms);
    }
    int received = ::recv(handle_, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0);
    return received;
}

bool TcpSocket::receive_exact(std::span<uint8_t> buffer, int timeout_ms) {
    size_t total = 0;
    while (total < buffer.size()) {
        int r = receive(buffer.subspan(total), timeout_ms);
        if (r <= 0) return false;
        total += static_cast<size_t>(r);
    }
    return true;
}

// TcpListener
TcpListener::TcpListener() : handle_(kInvalidSocket) {}

TcpListener::~TcpListener() {
    close();
}

TcpListener::TcpListener(TcpListener&& other) noexcept
    : handle_(other.handle_), port_(other.port_) {
    other.handle_ = kInvalidSocket;
    other.port_ = 0;
}

TcpListener& TcpListener::operator=(TcpListener&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        port_ = other.port_;
        other.handle_ = kInvalidSocket;
        other.port_ = 0;
    }
    return *this;
}

void TcpListener::close() {
    if (handle_ != kInvalidSocket) {
        SocketUtils::close_socket(handle_);
        handle_ = kInvalidSocket;
        port_ = 0;
    }
}

bool TcpListener::bind_and_listen(const std::string& bind_ip, uint16_t port, int backlog) {
    close();
    initialize_network();

    SocketHandle s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == kInvalidSocket) return false;

    SocketUtils::set_reuse_addr(s, true);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (bind_ip.empty() || bind_ip == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, bind_ip.c_str(), &addr.sin_addr);
    }

    if (::bind(s, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        SocketUtils::close_socket(s);
        return false;
    }

    if (port == 0) {
        socklen_t len = sizeof(addr);
        if (getsockname(s, reinterpret_cast<struct sockaddr*>(&addr), &len) == 0) {
            port = ntohs(addr.sin_port);
        }
    }

    if (::listen(s, backlog) != 0) {
        SocketUtils::close_socket(s);
        return false;
    }

    handle_ = s;
    port_ = port;
    return true;
}

std::optional<TcpSocket> TcpListener::accept(int timeout_ms) {
    if (handle_ == kInvalidSocket) return std::nullopt;

#if defined(SLUG_PLATFORM_POSIX)
    if (timeout_ms >= 0) {
        struct pollfd pfd{};
        pfd.fd = handle_;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret <= 0) return std::nullopt;
    }
#elif defined(SLUG_PLATFORM_WINDOWS)
    if (timeout_ms >= 0) {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(handle_, &read_set);
        timeval tv{};
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        int ret = select(0, &read_set, nullptr, nullptr, &tv);
        if (ret <= 0) return std::nullopt;
    }
#endif

    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    SocketHandle client_sock = ::accept(handle_, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
    if (client_sock == kInvalidSocket) return std::nullopt;

    char ip_buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &client_addr.sin_addr, ip_buf, sizeof(ip_buf));
    Endpoint peer{ip_buf, ntohs(client_addr.sin_port)};

    return TcpSocket(client_sock, peer);
}

// UdpSocket
UdpSocket::UdpSocket() : handle_(kInvalidSocket) {}

UdpSocket::~UdpSocket() {
    close();
}

UdpSocket::UdpSocket(UdpSocket&& other) noexcept
    : handle_(other.handle_), port_(other.port_) {
    other.handle_ = kInvalidSocket;
    other.port_ = 0;
}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        port_ = other.port_;
        other.handle_ = kInvalidSocket;
        other.port_ = 0;
    }
    return *this;
}

void UdpSocket::close() {
    if (handle_ != kInvalidSocket) {
        SocketUtils::close_socket(handle_);
        handle_ = kInvalidSocket;
        port_ = 0;
    }
}

bool UdpSocket::bind(const std::string& bind_ip, uint16_t port) {
    close();
    initialize_network();

    SocketHandle s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == kInvalidSocket) return false;

    SocketUtils::set_reuse_addr(s, true);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (bind_ip.empty() || bind_ip == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, bind_ip.c_str(), &addr.sin_addr);
    }

    if (::bind(s, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        SocketUtils::close_socket(s);
        return false;
    }

    if (port == 0) {
        socklen_t len = sizeof(addr);
        if (getsockname(s, reinterpret_cast<struct sockaddr*>(&addr), &len) == 0) {
            port = ntohs(addr.sin_port);
        }
    }

    handle_ = s;
    port_ = port;
    return true;
}

int UdpSocket::send_to(std::span<const uint8_t> data, const Endpoint& target) {
    if (handle_ == kInvalidSocket) return -1;
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(target.port);
    inet_pton(AF_INET, target.ip.c_str(), &addr.sin_addr);

    return ::sendto(handle_, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0,
                    reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr));
}

int UdpSocket::receive_from(std::span<uint8_t> buffer, Endpoint& sender, int timeout_ms) {
    if (handle_ == kInvalidSocket || buffer.empty()) return -1;
    if (timeout_ms >= 0) {
        SocketUtils::set_timeouts(handle_, timeout_ms);
    }

    struct sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    int received = ::recvfrom(handle_, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0,
                              reinterpret_cast<struct sockaddr*>(&addr), &len);
    if (received > 0) {
        char ip_buf[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &addr.sin_addr, ip_buf, sizeof(ip_buf));
        sender.ip = ip_buf;
        sender.port = ntohs(addr.sin_port);
    }
    return received;
}

} // namespace slug::platform
