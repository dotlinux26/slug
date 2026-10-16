#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <string_view>
#include <span>

#if defined(_WIN32) || defined(_WIN64)
    #define SLUG_PLATFORM_WINDOWS 1
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <io.h>
    #include <direct.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #define SLUG_PLATFORM_POSIX 1
    #if defined(__linux__)
        #define SLUG_PLATFORM_LINUX 1
    #elif defined(__APPLE__)
        #define SLUG_PLATFORM_MACOS 1
    #endif
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/stat.h>
    #include <sys/wait.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <poll.h>
    #include <errno.h>
#endif

namespace slug::platform {

inline void initialize_network() {
#if defined(SLUG_PLATFORM_WINDOWS)
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif
}

inline void cleanup_network() {
#if defined(SLUG_PLATFORM_WINDOWS)
    WSACleanup();
#endif
}

} // namespace slug::platform
