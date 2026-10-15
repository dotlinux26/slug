#include "src/bench/benchmark.hpp"
#include "src/crypto/crypto_suite.hpp"
#include "src/crypto/blake3_wrapper.hpp"
#include "src/crypto/sha256.hpp"
#include "src/crypto/xchacha20poly1305.hpp"
#include "src/ai/scanner.hpp"
#include "src/ai/stateful_audit.hpp"
#include "src/sync/chunker.hpp"
#include "src/core/utils.hpp"
#include "src/platform/fs.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <numeric>
#include <mutex>

namespace slug::bench {

using json = nlohmann::json;
using namespace std::chrono;

static std::recursive_mutex g_bench_mutex;
static FullBenchmarkReport g_latest_report;
static bool g_has_latest_report = false;

json FullBenchmarkReport::to_json() const {
    json j;
    j["timestamp"] = timestamp;

    j["crypto_suites"] = json::array();
    for (const auto& c : crypto_suites) {
        json obj;
        obj["suite_id"] = static_cast<int>(c.suite_id);
        obj["suite_name"] = c.suite_name;
        obj["kem_keygen_us"] = c.kem_keygen_us;
        obj["kem_encap_us"] = c.kem_encap_us;
        obj["kem_decap_us"] = c.kem_decap_us;
        obj["kem_ops_sec"] = c.kem_ops_sec;
        obj["sig_keygen_us"] = c.sig_keygen_us;
        obj["sig_sign_us"] = c.sig_sign_us;
        obj["sig_verify_us"] = c.sig_verify_us;
        obj["sig_ops_sec"] = c.sig_ops_sec;
        obj["cipher_encrypt_mb_sec"] = c.cipher_encrypt_mb_sec;
        obj["cipher_decrypt_mb_sec"] = c.cipher_decrypt_mb_sec;
        j["crypto_suites"].push_back(obj);
    }

    j["hashes"] = json::array();
    for (const auto& h : hashes) {
        json obj;
        obj["algorithm"] = h.algorithm;
        obj["throughput_mb_sec"] = h.throughput_mb_sec;
        obj["latency_us"] = h.latency_us;
        j["hashes"].push_back(obj);
    }

    j["ai"] = {
        {"scan_throughput_mb_sec", ai.scan_throughput_mb_sec},
        {"lines_per_sec", ai.lines_per_sec},
        {"cache_hit_lookup_us", ai.cache_hit_lookup_us}
    };

    j["sync"] = {
        {"chunking_throughput_mb_sec", sync.chunking_throughput_mb_sec},
        {"chunks_per_sec", sync.chunks_per_sec}
    };

    return j;
}

FullBenchmarkReport FullBenchmarkReport::from_json(const json& j) {
    FullBenchmarkReport r;
    r.timestamp = j.value("timestamp", 0ULL);

    if (j.contains("crypto_suites") && j["crypto_suites"].is_array()) {
        for (const auto& item : j["crypto_suites"]) {
            CryptoBenchResult cr;
            cr.suite_id = static_cast<core::SuiteID>(item.value("suite_id", 3));
            cr.suite_name = item.value("suite_name", "");
            cr.kem_keygen_us = item.value("kem_keygen_us", 0.0);
            cr.kem_encap_us = item.value("kem_encap_us", 0.0);
            cr.kem_decap_us = item.value("kem_decap_us", 0.0);
            cr.kem_ops_sec = item.value("kem_ops_sec", 0.0);
            cr.sig_keygen_us = item.value("sig_keygen_us", 0.0);
            cr.sig_sign_us = item.value("sig_sign_us", 0.0);
            cr.sig_verify_us = item.value("sig_verify_us", 0.0);
            cr.sig_ops_sec = item.value("sig_ops_sec", 0.0);
            cr.cipher_encrypt_mb_sec = item.value("cipher_encrypt_mb_sec", 0.0);
            cr.cipher_decrypt_mb_sec = item.value("cipher_decrypt_mb_sec", 0.0);
            r.crypto_suites.push_back(cr);
        }
    }

    if (j.contains("hashes") && j["hashes"].is_array()) {
        for (const auto& item : j["hashes"]) {
            HashBenchResult hr;
            hr.algorithm = item.value("algorithm", "");
            hr.throughput_mb_sec = item.value("throughput_mb_sec", 0.0);
            hr.latency_us = item.value("latency_us", 0.0);
            r.hashes.push_back(hr);
        }
    }

    if (j.contains("ai") && j["ai"].is_object()) {
        r.ai.scan_throughput_mb_sec = j["ai"].value("scan_throughput_mb_sec", 0.0);
        r.ai.lines_per_sec = j["ai"].value("lines_per_sec", 0.0);
        r.ai.cache_hit_lookup_us = j["ai"].value("cache_hit_lookup_us", 0.0);
    }

    if (j.contains("sync") && j["sync"].is_object()) {
        r.sync.chunking_throughput_mb_sec = j["sync"].value("chunking_throughput_mb_sec", 0.0);
        r.sync.chunks_per_sec = j["sync"].value("chunks_per_sec", 0.0);
    }

    return r;
}

CryptoBenchResult BenchmarkEngine::benchmark_crypto_suite(core::SuiteID suite_id, int iterations) {
    CryptoBenchResult res;
    res.suite_id = suite_id;
    auto suite = crypto::ICryptoSuite::create(suite_id);
    if (!suite) return res;

    res.suite_name = suite->name();

    // 1. KEM Keygen & Encap/Decap
    std::vector<double> kem_keygen_times;
    std::vector<double> kem_encap_times;
    std::vector<double> kem_decap_times;

    for (int i = 0; i < iterations; ++i) {
        auto t0 = high_resolution_clock::now();
        auto kp = suite->generate_kem_keypair();
        auto t1 = high_resolution_clock::now();
        kem_keygen_times.push_back(duration<double, std::micro>(t1 - t0).count());

        auto t2 = high_resolution_clock::now();
        auto ct = suite->encapsulate(kp.public_key);
        auto t3 = high_resolution_clock::now();
        kem_encap_times.push_back(duration<double, std::micro>(t3 - t2).count());

        auto t4 = high_resolution_clock::now();
        if (ct) {
            auto ss = suite->decapsulate(ct->ciphertext, kp.private_key);
            (void)ss;
        }
        auto t5 = high_resolution_clock::now();
        kem_decap_times.push_back(duration<double, std::micro>(t5 - t4).count());
    }

    res.kem_keygen_us = std::accumulate(kem_keygen_times.begin(), kem_keygen_times.end(), 0.0) / iterations;
    res.kem_encap_us = std::accumulate(kem_encap_times.begin(), kem_encap_times.end(), 0.0) / iterations;
    res.kem_decap_us = std::accumulate(kem_decap_times.begin(), kem_decap_times.end(), 0.0) / iterations;
    double total_kem_us = res.kem_keygen_us + res.kem_encap_us + res.kem_decap_us;
    res.kem_ops_sec = (total_kem_us > 0.0) ? (1000000.0 / total_kem_us) : 0.0;

    // 2. Signature Keygen, Sign, Verify
    std::vector<double> sig_keygen_times;
    std::vector<double> sig_sign_times;
    std::vector<double> sig_verify_times;
    std::vector<uint8_t> test_msg = {'S', 'L', 'U', 'G', '_', 'B', 'E', 'N', 'C', 'H'};

    for (int i = 0; i < iterations; ++i) {
        auto t0 = high_resolution_clock::now();
        auto skp = suite->generate_sig_keypair();
        auto t1 = high_resolution_clock::now();
        sig_keygen_times.push_back(duration<double, std::micro>(t1 - t0).count());

        auto t2 = high_resolution_clock::now();
        auto sig = suite->sign(test_msg, skp.private_key);
        auto t3 = high_resolution_clock::now();
        sig_sign_times.push_back(duration<double, std::micro>(t3 - t2).count());

        auto t4 = high_resolution_clock::now();
        if (sig) {
            bool ok = suite->verify(test_msg, *sig, skp.public_key);
            (void)ok;
        }
        auto t5 = high_resolution_clock::now();
        sig_verify_times.push_back(duration<double, std::micro>(t5 - t4).count());
    }

    res.sig_keygen_us = std::accumulate(sig_keygen_times.begin(), sig_keygen_times.end(), 0.0) / iterations;
    res.sig_sign_us = std::accumulate(sig_sign_times.begin(), sig_sign_times.end(), 0.0) / iterations;
    res.sig_verify_us = std::accumulate(sig_verify_times.begin(), sig_verify_times.end(), 0.0) / iterations;
    double total_sig_us = res.sig_keygen_us + res.sig_sign_us + res.sig_verify_us;
    res.sig_ops_sec = (total_sig_us > 0.0) ? (1000000.0 / total_sig_us) : 0.0;

    // 3. Symmetric Cipher Speed (XChaCha20-Poly1305 on 1 MB buffer)
    size_t cipher_buf_size = 1024 * 1024; // 1 MB
    std::vector<uint8_t> plain(cipher_buf_size, 0x42);
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 24> nonce{};
    std::vector<uint8_t> aad = {'A', 'A', 'D'};

    int cipher_iters = std::max(5, iterations / 5);
    auto enc_t0 = high_resolution_clock::now();
    std::vector<uint8_t> cipher;
    for (int i = 0; i < cipher_iters; ++i) {
        cipher = crypto::XChaCha20Poly1305::encrypt(plain, key, nonce, aad);
    }
    auto enc_t1 = high_resolution_clock::now();
    double enc_sec = duration<double>(enc_t1 - enc_t0).count();
    res.cipher_encrypt_mb_sec = (static_cast<double>(cipher_buf_size * cipher_iters) / (1024.0 * 1024.0)) / enc_sec;

    auto dec_t0 = high_resolution_clock::now();
    for (int i = 0; i < cipher_iters; ++i) {
        auto dec = crypto::XChaCha20Poly1305::decrypt(cipher, key, nonce, aad);
        (void)dec;
    }
    auto dec_t1 = high_resolution_clock::now();
    double dec_sec = duration<double>(dec_t1 - dec_t0).count();
    res.cipher_decrypt_mb_sec = (static_cast<double>(cipher_buf_size * cipher_iters) / (1024.0 * 1024.0)) / dec_sec;

    return res;
}

HashBenchResult BenchmarkEngine::benchmark_blake3(size_t buffer_size, int iterations) {
    HashBenchResult res;
    res.algorithm = "BLAKE3 (Tree-hashing / 256-bit)";

    std::vector<uint8_t> buf(buffer_size, 0x5A);

    auto t0 = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto h = crypto::Blake3::hash(buf);
        (void)h;
    }
    auto t1 = high_resolution_clock::now();

    double sec = duration<double>(t1 - t0).count();
    double total_mb = static_cast<double>(buffer_size * iterations) / (1024.0 * 1024.0);
    res.throughput_mb_sec = total_mb / sec;
    res.latency_us = (sec * 1000000.0) / iterations;
    return res;
}

HashBenchResult BenchmarkEngine::benchmark_sha256(size_t buffer_size, int iterations) {
    HashBenchResult res;
    res.algorithm = "SHA-256 (OpenSSL EVP)";

    std::vector<uint8_t> buf(buffer_size, 0x5A);

    auto t0 = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto h = crypto::Sha256::hash(buf);
        (void)h;
    }
    auto t1 = high_resolution_clock::now();

    double sec = duration<double>(t1 - t0).count();
    double total_mb = static_cast<double>(buffer_size * iterations) / (1024.0 * 1024.0);
    res.throughput_mb_sec = total_mb / sec;
    res.latency_us = (sec * 1000000.0) / iterations;
    return res;
}

AiBenchResult BenchmarkEngine::benchmark_ai_guard(int iterations) {
    AiBenchResult res;
    ai::AiScanner scanner;

    // Synthesize realistic code lines
    std::string sample_code =
        "import os\n"
        "import requests\n"
        "def fetch_data(user_id):\n"
        "    url = f'https://api.service.internal/v1/users/{user_id}'\n"
        "    headers = {'Accept': 'application/json'}\n"
        "    resp = requests.get(url, headers=headers)\n"
        "    return resp.json()\n"
        "if __name__ == '__main__':\n"
        "    print(fetch_data(42))\n";

    size_t sample_size = sample_code.size();
    size_t line_count = 9;

    auto t0 = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto finding = scanner.scan_content("bench_file.py", sample_code, false);
        (void)finding;
    }
    auto t1 = high_resolution_clock::now();

    double sec = duration<double>(t1 - t0).count();
    double total_mb = static_cast<double>(sample_size * iterations) / (1024.0 * 1024.0);
    res.scan_throughput_mb_sec = total_mb / sec;
    res.lines_per_sec = static_cast<double>(line_count * iterations) / sec;

    // Cache hit lookup speed
    auto temp_dir = std::filesystem::temp_directory_path() / "slug_bench_ai";
    platform::PathUtils::ensure_directory(temp_dir);
    auto idx_file = temp_dir / "index.db";
    ai::StatefulAuditIndex audit_idx(idx_file);
    std::string test_path = "src/main.rs";
    std::string test_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    ai::AuditIndexEntry entry;
    entry.file_path = test_path;
    entry.blake3_hash = test_hash;
    entry.status = core::AuditStatus::CLEAN;
    entry.reason = "Clean";
    audit_idx.update_entry(entry);

    int cache_iters = 10000;
    auto ct0 = high_resolution_clock::now();
    for (int i = 0; i < cache_iters; ++i) {
        auto st = audit_idx.check_cached_status(test_path, test_hash);
        (void)st;
    }
    auto ct1 = high_resolution_clock::now();
    res.cache_hit_lookup_us = duration<double, std::micro>(ct1 - ct0).count() / cache_iters;

    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);

    return res;
}

SyncBenchResult BenchmarkEngine::benchmark_chunker(size_t buffer_size, int iterations) {
    SyncBenchResult res;
    std::vector<uint8_t> buf(buffer_size, 0xA5);

    auto t0 = high_resolution_clock::now();
    size_t total_chunks = 0;
    for (int i = 0; i < iterations; ++i) {
        auto chunks = sync::Chunker::chunk_buffer(buf);
        total_chunks += chunks.size();
    }
    auto t1 = high_resolution_clock::now();

    double sec = duration<double>(t1 - t0).count();
    double total_mb = static_cast<double>(buffer_size * iterations) / (1024.0 * 1024.0);
    res.chunking_throughput_mb_sec = total_mb / sec;
    res.chunks_per_sec = static_cast<double>(total_chunks) / sec;
    return res;
}

FullBenchmarkReport BenchmarkEngine::run_all(bool quick) {
    FullBenchmarkReport rep;
    rep.timestamp = core::Utils::current_timestamp();

    int crypto_iters = quick ? 20 : 50;
    int hash_iters = quick ? 3 : 5;
    size_t hash_buf = quick ? (5 * 1024 * 1024) : (10 * 1024 * 1024);

    // 1. Bench all 3 crypto suites
    rep.crypto_suites.push_back(benchmark_crypto_suite(core::SuiteID::SUITE_1_CLASSICAL, crypto_iters));
    rep.crypto_suites.push_back(benchmark_crypto_suite(core::SuiteID::SUITE_2_MODERN, crypto_iters));
    rep.crypto_suites.push_back(benchmark_crypto_suite(core::SuiteID::SUITE_3_PURE_PQC, crypto_iters));

    // 2. Hash shootout
    rep.hashes.push_back(benchmark_blake3(hash_buf, hash_iters));
    rep.hashes.push_back(benchmark_sha256(hash_buf, hash_iters));

    // 3. AI Guard
    rep.ai = benchmark_ai_guard(quick ? 200 : 500);

    // 4. Sync Chunker
    rep.sync = benchmark_chunker(hash_buf, hash_iters);

    set_latest_report(rep);
    return rep;
}

void BenchmarkEngine::print_report(const FullBenchmarkReport& report) {
    std::cout << "\n================================================================================" << std::endl;
    std::cout << "                 SLUG PERFORMANCE & SECURITY BENCHMARK REPORT                   " << std::endl;
    std::cout << "================================================================================" << std::endl;

    auto get_suite_label = [](const CryptoBenchResult& c) -> std::string {
        if (c.suite_id == core::SuiteID::SUITE_1_CLASSICAL) return "Suite 1: Classical (Ed25519/X25519)";
        if (c.suite_id == core::SuiteID::SUITE_2_MODERN)    return "Suite 2: Modern (BLAKE3/X25519)";
        if (c.suite_id == core::SuiteID::SUITE_3_PURE_PQC)  return "Suite 3: PurePQC (ML-KEM/ML-DSA)";
        return c.suite_name;
    };

    // Cryptographic Suites
    std::cout << "\n[1] CRYPTOGRAPHIC SUITE PERFORMANCE COMPARISON:" << std::endl;
    std::cout << std::left
              << std::setw(38) << "SUITE"
              << std::setw(14) << "KEM KEYGEN"
              << std::setw(14) << "KEM ENCAP"
              << std::setw(14) << "KEM DECAP"
              << std::setw(16) << "KEM OPS/SEC"
              << std::endl;
    std::cout << std::string(96, '-') << std::endl;

    for (const auto& c : report.crypto_suites) {
        std::cout << std::left
                  << std::setw(38) << get_suite_label(c)
                  << std::setw(14) << (std::to_string(static_cast<int>(c.kem_keygen_us)) + " us")
                  << std::setw(14) << (std::to_string(static_cast<int>(c.kem_encap_us)) + " us")
                  << std::setw(14) << (std::to_string(static_cast<int>(c.kem_decap_us)) + " us")
                  << std::setw(16) << (std::to_string(static_cast<int>(c.kem_ops_sec)) + " ops/s")
                  << std::endl;
    }

    std::cout << "\n" << std::left
              << std::setw(38) << "SUITE"
              << std::setw(14) << "SIG KEYGEN"
              << std::setw(14) << "SIG SIGN"
              << std::setw(14) << "SIG VERIFY"
              << std::setw(16) << "SIG OPS/SEC"
              << std::endl;
    std::cout << std::string(96, '-') << std::endl;

    for (const auto& c : report.crypto_suites) {
        std::cout << std::left
                  << std::setw(38) << get_suite_label(c)
                  << std::setw(14) << (std::to_string(static_cast<int>(c.sig_keygen_us)) + " us")
                  << std::setw(14) << (std::to_string(static_cast<int>(c.sig_sign_us)) + " us")
                  << std::setw(14) << (std::to_string(static_cast<int>(c.sig_verify_us)) + " us")
                  << std::setw(16) << (std::to_string(static_cast<int>(c.sig_ops_sec)) + " ops/s")
                  << std::endl;
    }

    std::cout << "\n" << std::left
              << std::setw(38) << "SUITE"
              << std::setw(24) << "XCHACHA20 ENCRYPT"
              << std::setw(24) << "XCHACHA20 DECRYPT"
              << std::endl;
    std::cout << std::string(86, '-') << std::endl;
    for (const auto& c : report.crypto_suites) {
        std::ostringstream s1, s2;
        s1 << std::fixed << std::setprecision(1) << c.cipher_encrypt_mb_sec << " MB/s";
        s2 << std::fixed << std::setprecision(1) << c.cipher_decrypt_mb_sec << " MB/s";
        std::cout << std::left
                  << std::setw(38) << get_suite_label(c)
                  << std::setw(24) << s1.str()
                  << std::setw(24) << s2.str()
                  << std::endl;
    }

    // Hashing Shootout
    std::cout << "\n[2] HASH ENGINE SHOOTOUT:" << std::endl;
    std::cout << std::left
              << std::setw(34) << "ALGORITHM"
              << std::setw(22) << "THROUGHPUT (MB/s)"
              << std::setw(20) << "LATENCY (10MB)"
              << std::endl;
    std::cout << std::string(76, '-') << std::endl;
    for (const auto& h : report.hashes) {
        std::ostringstream s_tp, s_lat;
        s_tp << std::fixed << std::setprecision(1) << h.throughput_mb_sec << " MB/s";
        s_lat << std::fixed << std::setprecision(2) << (h.latency_us / 1000.0) << " ms";
        std::cout << std::left
                  << std::setw(34) << h.algorithm
                  << std::setw(22) << s_tp.str()
                  << std::setw(20) << s_lat.str()
                  << std::endl;
    }
    if (report.hashes.size() >= 2 && report.hashes[1].throughput_mb_sec > 0.0) {
        double ratio = report.hashes[0].throughput_mb_sec / report.hashes[1].throughput_mb_sec;
        std::cout << "\n [*] BLAKE3 is " << std::fixed << std::setprecision(2) << ratio << "x faster than SHA-256." << std::endl;
    }

    // AI Guard
    std::cout << "\n[3] STATEFUL AI SECRET GUARD & CACHE:" << std::endl;
    std::cout << "  - Heuristic Scan Throughput: " << std::fixed << std::setprecision(1) << report.ai.scan_throughput_mb_sec << " MB/s ("
              << static_cast<int>(report.ai.lines_per_sec) << " lines/sec)" << std::endl;
    std::cout << "  - Stateful Index Cache Hit:  " << std::fixed << std::setprecision(3) << report.ai.cache_hit_lookup_us << " us / file lookup (0ms overhead on unchanged files)" << std::endl;

    // Delta Sync Chunker
    std::cout << "\n[4] DELTA SYNC PIPELINE (64 KiB Content-Addressable Chunker):" << std::endl;
    std::cout << "  - Chunking Throughput:       " << std::fixed << std::setprecision(1) << report.sync.chunking_throughput_mb_sec << " MB/s" << std::endl;
    std::cout << "  - Chunk Rate:                " << static_cast<int>(report.sync.chunks_per_sec) << " chunks/sec" << std::endl;
    std::cout << "================================================================================\n" << std::endl;
}

FullBenchmarkReport BenchmarkEngine::get_latest_report() {
    std::lock_guard<std::recursive_mutex> lock(g_bench_mutex);
    if (!g_has_latest_report) {
        // Run initial quick benchmark if not yet available
        g_latest_report = run_all(true);
        g_has_latest_report = true;
    }
    return g_latest_report;
}

void BenchmarkEngine::set_latest_report(const FullBenchmarkReport& report) {
    std::lock_guard<std::recursive_mutex> lock(g_bench_mutex);
    g_latest_report = report;
    g_has_latest_report = true;
}

} // namespace slug::bench
