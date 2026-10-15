# Contributing to Slug

Thank you for your interest in contributing to **Slug**! We welcome bug reports, performance enhancements, cryptographic audits, documentation improvements, and pull requests.

Slug is licensed under the [Apache License, Version 2.0](LICENSE). By contributing to this repository, you agree that your contributions will be licensed under the same terms.

---

## 1. Development Principles & Code Standards

To preserve Slug's security, performance, and portability guarantees, all contributions must adhere to the following core guidelines:

### Core Engineering Requirements
1. **Modern C++20**: Use standard C++20 features (`std::span`, `std::filesystem`, structured bindings, `std::chrono`).
2. **Zero Runtime Dependencies**: The Linux release must remain a **100% static binary** (`bin/slug-static`). Do not introduce runtime shared library dependencies that break portability across minimal distros (like Alpine) or scratch Docker containers.
3. **Cross-Platform Compatibility**: Code must compile and function identically on Linux (GCC/Clang) and Microsoft Windows (MSVC C++20). Always wrap platform-specific APIs inside `src/platform/`.
4. **Strictly Professional CLI Output (Zero Emoji / Sticker Policy)**:
   - Do **NOT** use emojis, icons, or stickers in terminal output, logs, help screens, or error messages.
   - Use standard Unix prefix conventions:
     - `[*]` for progress or state notices
     - `[+]` for successful actions
     - `[-]` for errors and failures
     - `[!]` for security alerts and warnings
5. **Constant-Time Cryptographic Verification**: Never use `==` or standard `strcmp` for comparing hashes, tokens, or TOTP codes. Always use `core::Utils::constant_time_compare` (backed by `CRYPTO_memcmp`).
6. **Memory Sanitization**: Sensitive cryptographic keys and decrypted plaintext secrets must be wiped with `OPENSSL_cleanse` before freeing or going out of scope.

---

## 2. Building & Testing Locally

### Prerequisites
- Linux: `g++` (>= 11) or `clang++` (>= 14), `make`, `libssl-dev`, `zlib1g-dev`, `libzstd-dev`.
- Windows: Visual Studio 2022 (MSVC) + CMake 3.20+ + OpenSSL.

### Building
```bash
# Build dynamic development binary
make -j$(nproc)

# Build fully static release binary
make static -j$(nproc)
```

### Running Test Suite
Before opening a pull request, verify that the automated integration test suite passes:
```bash
bash scripts/test_local.sh
```
All tests must report `[PASS]` (46/46 passed, 0 failed).

### Running Benchmarks
Verify cryptographic throughput:
```bash
./bin/slug bench --quick
```

---

## 3. Pull Request Guidelines

1. **Branch Naming**: Use descriptive branch names:
   - `feat/<feature-name>`
   - `fix/<bug-description>`
   - `perf/<optimization>`
   - `docs/<documentation-update>`
2. **Commit Messages**: Follow standard conventional commits format:
   - `feat: add hybrid post-quantum key exchange`
   - `fix: resolve race condition in totp sliding window`
   - `perf: optimize blake3 chunk hashing pipeline`
   - `docs: update windows installation guide`
3. **Tests Required**: Any new command, flag, or security check must include a corresponding automated test case in `scripts/test_local.sh`.
4. **No Compiler Warnings**: Code must compile cleanly with `-Wall -Wextra`.

---

## 4. Reporting Security Flaws

Please **do not** open public GitHub issues for security vulnerabilities. Review our [SECURITY.md](SECURITY.md) for confidential disclosure instructions via GitHub Advisories or direct email to `admin@ghedahaui.online`.
