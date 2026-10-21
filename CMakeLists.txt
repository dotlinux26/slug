cmake_minimum_required(VERSION 3.20)
project(slug VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(SLUG_BUILD_STATIC "Build statically linked executable" OFF)

# Portable BLAKE3 without dynamic vector assembly
add_definitions(
    -DBLAKE3_NO_SSE2
    -DBLAKE3_NO_SSE41
    -DBLAKE3_NO_AVX2
    -DBLAKE3_NO_AVX512
    -DSQLITE_DQS=0
    -DSQLITE_THREADSAFE=1
    -DSQLITE_DEFAULT_MEMSTATUS=0
    -DSQLITE_OMIT_DEPRECATED
    -DSQLITE_OMIT_PROGRESS_CALLBACK
    -DSQLITE_OMIT_SHARED_CACHE
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

set(SLUG_SOURCES
    third_party/sqlite/sqlite3.c
    third_party/blake3/blake3.c
    third_party/blake3/blake3_portable.c
    third_party/blake3/blake3_dispatch.c
    src/main.cpp
    src/platform/socket.cpp
    src/platform/fs.cpp
    src/platform/process.cpp
    src/core/utils.cpp
    src/core/logger.cpp
    src/core/acl.cpp
    src/core/audit.cpp
    src/core/workspace.cpp
    src/core/connection_manager.cpp
    src/core/vfs.cpp
    src/crypto/xchacha20poly1305.cpp
    src/crypto/blake3_wrapper.cpp
    src/crypto/sha256.cpp
    src/crypto/totp.cpp
    src/crypto/crypto_suite.cpp
    src/crypto/suite_classical.cpp
    src/crypto/suite_modern.cpp
    src/crypto/suite_pqc.cpp
    src/policy/gitignore.cpp
    src/policy/rules.cpp
    src/policy/filter.cpp
    src/ai/stateful_audit.cpp
    src/ai/scanner.cpp
    src/sync/chunker.cpp
    src/sync/manifest.cpp
    src/sync/delta.cpp
    src/net/control_server.cpp
    src/net/data_server.cpp
    src/net/client.cpp
    src/net/web_server.cpp
    src/envshield/envshield.cpp
    src/bench/benchmark.cpp
)

# Embed Windows icon and version info via resource compiler (MSVC only)
if(WIN32 AND MSVC)
    # slug.rc references assets/slug-icon.ico relative to project root
    set(SLUG_RC_FILE "${CMAKE_CURRENT_SOURCE_DIR}/slug.rc")
    if(EXISTS "${SLUG_RC_FILE}")
        list(APPEND SLUG_SOURCES "${SLUG_RC_FILE}")
        message(STATUS "[slug] Embedding Windows resource: ${SLUG_RC_FILE}")
    else()
        message(WARNING "[slug] slug.rc not found — icon will NOT be embedded in slug.exe")
    endif()
endif()

add_executable(slug ${SLUG_SOURCES})

# Platform-specific link libraries & configuration
if(WIN32)
    target_link_libraries(slug PRIVATE ws2_32 crypt32 bcrypt advapi32 user32 iphlpapi ole32 shell32 uuid)
    # Statically link C/C++ runtime on MSVC (/MT)
    if(MSVC)
        set_property(TARGET slug PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        target_compile_options(slug PRIVATE /utf-8 /W3 /EHsc)
        target_compile_definitions(slug PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()
    # Find OpenSSL on Windows
    if(NOT OPENSSL_ROOT_DIR AND EXISTS "C:/Program Files/OpenSSL-Win64")
        set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
    endif()
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        target_link_libraries(slug PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    elseif(EXISTS "C:/Program Files/OpenSSL-Win64")
        set(OPENSSL_INCLUDE_DIR "C:/Program Files/OpenSSL-Win64/include")
        find_library(OPENSSL_CRYPTO_LIBRARY NAMES libcrypto crypto PATHS "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD" "C:/Program Files/OpenSSL-Win64/lib")
        find_library(OPENSSL_SSL_LIBRARY NAMES libssl ssl PATHS "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD" "C:/Program Files/OpenSSL-Win64/lib")
        target_include_directories(slug PRIVATE ${OPENSSL_INCLUDE_DIR})
        target_link_libraries(slug PRIVATE ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
    else()
        find_package(OpenSSL REQUIRED)
        target_link_libraries(slug PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()

elseif(APPLE)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(slug PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread)

else()
    # Linux / POSIX
    find_package(OpenSSL REQUIRED)
    target_link_libraries(slug PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread ${CMAKE_DL_LIBS})

    if(SLUG_BUILD_STATIC)
        target_link_options(slug PRIVATE -static -static-libgcc -static-libstdc++)
        find_package(ZLIB REQUIRED)
        target_link_libraries(slug PRIVATE ZLIB::ZLIB zstd)
    endif()
endif()

install(TARGETS slug DESTINATION bin)
