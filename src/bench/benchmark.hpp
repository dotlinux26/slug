#pragma once

#include "src/core/types.hpp"
#include "third_party/json/json.hpp"
#include <string>
#include <vector>
#include <chrono>

namespace slug::bench {

struct CryptoBenchResult {
    core::SuiteID suite_id{core::SuiteID::SUITE_3_PURE_PQC};
    std::string suite_name;
    double kem_keygen_us{0.0};
    double kem_encap_us{0.0};
    double kem_decap_us{0.0};
    double kem_ops_sec{0.0};

    double sig_keygen_us{0.0};
    double sig_sign_us{0.0};
    double sig_verify_us{0.0};
    double sig_ops_sec{0.0};

    double cipher_encrypt_mb_sec{0.0};
    double cipher_decrypt_mb_sec{0.0};
};

struct HashBenchResult {
    std::string algorithm;
    double throughput_mb_sec{0.0};
    double latency_us{0.0};
};

struct AiBenchResult {
    double scan_throughput_mb_sec{0.0};
    double lines_per_sec{0.0};
    double cache_hit_lookup_us{0.0};
};

struct SyncBenchResult {
    double chunking_throughput_mb_sec{0.0};
    double chunks_per_sec{0.0};
};

struct FullBenchmarkReport {
    uint64_t timestamp{0};
    std::vector<CryptoBenchResult> crypto_suites;
    std::vector<HashBenchResult> hashes;
    AiBenchResult ai;
    SyncBenchResult sync;

    nlohmann::json to_json() const;
    static FullBenchmarkReport from_json(const nlohmann::json& j);
};

class BenchmarkEngine {
public:
    static CryptoBenchResult benchmark_crypto_suite(core::SuiteID suite_id, int iterations = 50);
    static HashBenchResult benchmark_blake3(size_t buffer_size = 10 * 1024 * 1024, int iterations = 5);
    static HashBenchResult benchmark_sha256(size_t buffer_size = 10 * 1024 * 1024, int iterations = 5);
    static AiBenchResult benchmark_ai_guard(int iterations = 500);
    static SyncBenchResult benchmark_chunker(size_t buffer_size = 10 * 1024 * 1024, int iterations = 5);

    static FullBenchmarkReport run_all(bool quick = false);
    static void print_report(const FullBenchmarkReport& report);

    // Thread-safe access to latest benchmark cache
    static FullBenchmarkReport get_latest_report();
    static void set_latest_report(const FullBenchmarkReport& report);
};

} // namespace slug::bench
