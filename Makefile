CXX ?= g++
CC ?= gcc
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra -pthread -I. -I./third_party -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512
CFLAGS ?= -O2 -I. -I./third_party -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512
LDFLAGS ?= -pthread -lssl -lcrypto

STATIC_FLAGS = -static -static-libgcc -static-libstdc++
STATIC_LDFLAGS = -pthread -lssl -lcrypto -lzstd -lz

TARGET = bin/slug
TARGET_STATIC = bin/slug-static

SRC_C = third_party/blake3/blake3.c \
        third_party/blake3/blake3_portable.c \
        third_party/blake3/blake3_dispatch.c

SRC_CXX = src/main.cpp \
          src/platform/socket.cpp \
          src/platform/fs.cpp \
          src/platform/process.cpp \
          src/core/utils.cpp \
          src/core/acl.cpp \
          src/core/audit.cpp \
          src/core/workspace.cpp \
          src/core/connection_manager.cpp \
          src/core/vfs.cpp \
          src/crypto/xchacha20poly1305.cpp \
          src/crypto/blake3_wrapper.cpp \
          src/crypto/sha256.cpp \
          src/crypto/totp.cpp \
          src/crypto/crypto_suite.cpp \
          src/crypto/suite_classical.cpp \
          src/crypto/suite_modern.cpp \
          src/crypto/suite_pqc.cpp \
          src/policy/gitignore.cpp \
          src/policy/rules.cpp \
          src/policy/filter.cpp \
          src/ai/stateful_audit.cpp \
          src/ai/scanner.cpp \
          src/sync/chunker.cpp \
          src/sync/manifest.cpp \
          src/sync/delta.cpp \
          src/net/control_server.cpp \
          src/net/data_server.cpp \
          src/net/client.cpp \
          src/net/web_server.cpp \
          src/envshield/envshield.cpp \
          src/bench/benchmark.cpp

OBJ_C = $(SRC_C:.c=.o)
OBJ_CXX = $(SRC_CXX:.cpp=.o)
OBJS = $(OBJ_C) $(OBJ_CXX)

.PHONY: all static clean test dirs

all: dirs $(TARGET)

dirs:
	@mkdir -p bin

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) -o $@
	@echo "[+] Built dynamic binary: $(TARGET)"

static: dirs $(OBJS)
	$(CXX) $(STATIC_FLAGS) $(OBJS) $(STATIC_LDFLAGS) -o $(TARGET_STATIC)
	@echo "[+] Built fully static binary: $(TARGET_STATIC)"
	@file $(TARGET_STATIC) || true
	@ldd $(TARGET_STATIC) 2>&1 || true

test: all
	@bash scripts/test_local.sh

clean:
	rm -f $(OBJS) $(TARGET) $(TARGET_STATIC)
	rm -rf bin
