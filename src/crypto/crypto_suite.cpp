#include "src/crypto/crypto_suite.hpp"

namespace slug::crypto {

std::unique_ptr<ICryptoSuite> create_suite_classical();
std::unique_ptr<ICryptoSuite> create_suite_modern();
std::unique_ptr<ICryptoSuite> create_suite_pqc();

std::unique_ptr<ICryptoSuite> ICryptoSuite::create(core::SuiteID id) {
    switch (id) {
        case core::SuiteID::SUITE_1_CLASSICAL:
            return create_suite_classical();
        case core::SuiteID::SUITE_2_MODERN:
            return create_suite_modern();
        case core::SuiteID::SUITE_3_PURE_PQC:
        default:
            return create_suite_pqc();
    }
}

} // namespace slug::crypto
