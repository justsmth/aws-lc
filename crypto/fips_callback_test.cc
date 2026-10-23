// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// Tests for the AWSLC_FIPS_FAILURE_CALLBACK build mode. This file defines
// |AWS_LC_fips_failure_callback|, so in a callback build every FIPS failure in
// the crypto_test process is routed here instead of aborting.
//
// The tests are driven by two environment variables set by
// tests/ci/run_fips_callback_tests.sh:
//
//   FIPS_CALLBACK_TEST_EXPECTED_FAILURE names the self-test that the harness
//   has broken, either by patching a KAT input in the binary with
//   util/fipstools/break-kat.go or (for the *_PWCT values) by also setting
//   BORINGSSL_FIPS_BREAK_TEST in a BORINGSSL_FIPS_BREAK_TESTS build.
//
// Without the variable the tests check that a healthy module never invokes the
// callback. With it they check that the failure is reported exactly once per
// failing test, that the operation which triggered it fails, and that the
// module stays in the error state afterwards (see FIPS.md).

#include <gtest/gtest.h>
#include <openssl/crypto.h>
#include <openssl/curve25519.h>
#include <openssl/dh.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/service_indicator.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "internal.h"

extern "C" {
void AWS_LC_fips_failure_callback(const char *message);
}

// The callback can run from the module's power-on constructor, before the C++
// static initialisers of this file, so everything it touches must be plain
// zero-initialised data.
static const int kMaxRecordedMessages = 16;
static const size_t kMaxRecordedLength = 128;
static int callback_call_count = 0;
static char callback_messages[kMaxRecordedMessages][kMaxRecordedLength];

void AWS_LC_fips_failure_callback(const char *message) {
  // KAT failure messages carry multi-line hex dumps of the expected and
  // calculated values. Only the first line identifies the failure, so only that
  // is recorded and compared.
  const size_t first_line_len = strcspn(message, "\n");
  if (callback_call_count < kMaxRecordedMessages) {
    size_t len = first_line_len;
    if (len >= kMaxRecordedLength) {
      len = kMaxRecordedLength - 1;
    }
    memcpy(callback_messages[callback_call_count], message, len);
    callback_messages[callback_call_count][len] = 0;
  }
  callback_call_count++;
  // The shell harness looks for this line when the failure is fatal and the
  // process aborts before any test runs.
  fprintf(stderr, "AWS_LC_fips_failure_callback: %.*s\n", (int)first_line_len,
          message);
  fflush(stderr);
}

namespace {

// Group identifies which lazily self-tested algorithm first observes a broken
// test. Start-up KATs put the module into the error state before |main| runs,
// so every operation fails for them.
enum Group {
  kStartup,
  kRSA,
  kECC,
  kFFDH,
  kMLKEM,
  kMLDSA,
  kEdDSA,
  kEdDSAph,
};

struct BrokenTest {
  const char *name;
  Group group;
  // The first line of each message the callback receives, in order, while
  // running |RunOperations|. Where a failure is reported more than once (a
  // KAT mismatch followed by the enclosing self-test, or a start-up KAT
  // followed by "Power on self test failed") the later messages are delivered
  // after the module has already entered the error state, which shows that
  // the error state does not suppress the callback.
  std::vector<const char *> messages;
};

const std::vector<BrokenTest> &BrokenTests() {
  static const std::vector<BrokenTest> kTests = {
      // Pairwise consistency tests, broken at run time with
      // BORINGSSL_FIPS_BREAK_TEST. The ML-KEM and ML-DSA KATs include key
      // generation, so there the lazy KAT fails before the application's
      // keygen is reached.
      {"RSA_PWCT", kRSA, {"RSA keygen checks failed"}},
      {"EC_PWCT", kECC, {"EC keygen checks failed"}},
      {"EDDSA_PWCT", kEdDSA, {"Ed25519 keygen PCT failed"}},
      {"MLKEM_PWCT", kMLKEM,
       {"ML-KEM keygen PCT failed", "ML-KEM self tests failed"}},
      {"MLDSA_PWCT", kMLDSA,
       {"ML-DSA keygen PCT failed", "ML-DSA self tests failed"}},

      // Start-up KATs, broken by patching the binary. These fail inside the
      // module constructor. (SHA-256 and HMAC-SHA-256 are not listed: they are
      // the CASTs that guard the integrity test, so breaking them aborts the
      // process even with a callback, and the shell harness checks that.)
      {"AES-CBC-encrypt", kStartup,
       {"AES-CBC-encrypt KAT failed.", "Power on self test failed"}},
      {"AES-CBC-decrypt", kStartup,
       {"AES-CBC-decrypt KAT failed.", "Power on self test failed"}},
      {"AES-GCM-encrypt", kStartup,
       {"AES-GCM-encrypt KAT failed.", "Power on self test failed"}},
      {"AES-GCM-decrypt", kStartup,
       {"AES-GCM-decrypt KAT failed because EVP_AEAD_CTX_open failed",
        "Power on self test failed"}},
      {"AES-KWP-unwrap", kStartup,
       {"AES-KWP-unwrap failed.", "Power on self test failed"}},
      {"AES-KWP-wrap", kStartup,
       {"AES-KWP-wrap failed.", "Power on self test failed"}},
      {"DRBG", kStartup,
       {"DRBG Generate KAT failed.", "CTR-DRBG failed",
        "Power on self test failed"}},
      {"DRBG-reseed", kStartup,
       {"DRBG-reseed KAT failed.", "CTR-DRBG failed",
        "Power on self test failed"}},
      {"SHA-1", kStartup, {"SHA-1 KAT failed.", "Power on self test failed"}},
      {"SHA-512", kStartup,
       {"SHA-512 KAT failed.", "Power on self test failed"}},
      {"SHA3-256", kStartup,
       {"SHA3-256 KAT failed.", "Power on self test failed"}},
      {"TLS-KDF", kStartup,
       {"TLS-KDF KAT failed.", "Power on self test failed"}},
      {"TLS13-KDF", kStartup,
       {"TLS13-KDF KAT failed.", "Power on self test failed"}},
      {"HKDF-SHA-256", kStartup,
       {"HKDF-SHA-256 KAT failed.", "Power on self test failed"}},
      {"KBKDF", kStartup,
       {"KBKDF-CTR-HMAC-SHA-256 KAT failed.", "Power on self test failed"}},
      {"PBKDF2", kStartup,
       {"PBKDF2 KAT failed.", "Power on self test failed"}},
      {"SSKDF", kStartup,
       {"SSKDF_digest KAT failed.", "Power on self test failed"}},

      // Lazy KATs, broken by patching the binary. These fail on first use of
      // the algorithm and must make that first use fail.
      {"RSA-sign", kRSA, {"RSA-sign KAT failed.", "RSA self tests failed"}},
      {"RSA-verify", kRSA, {"RSA-verify KAT failed", "RSA self tests failed"}},
      {"ECDSA-sign", kECC,
       {"ECDSA-sign signature failed.", "ECDSA-sign KAT failed",
        "ECC self tests failed"}},
      {"ECDSA-verify", kECC,
       {"ECDSA-verify KAT failed", "ECC self tests failed"}},
      {"Z-computation", kECC,
       {"Z-computation failed.", "ECC self tests failed"}},
      {"FFDH", kFFDH, {"FFDH self tests failed"}},
      {"ED25519-sign", kEdDSA,
       {"ED25519-sign failed.", "ED25519-sign failed",
        "EdDSA self tests failed"}},
      {"ED25519-verify", kEdDSA,
       {"ED25519-verify failed", "EdDSA self tests failed"}},
      {"ED25519ph-sign", kEdDSAph,
       {"ED25519ph-sign failed.", "EdDSA-ph self tests failed"}},
      {"ED25519ph-verify", kEdDSAph,
       {"ED25519ph-verify failed", "EdDSA-ph self tests failed"}},
      {"ML-KEM-keyGen-decaps", kMLKEM,
       {"ML-KEM-keyGen-decaps failed.", "ML-KEM self tests failed"}},
      {"ML-KEM-keyGen-encaps", kMLKEM,
       {"ML-KEM-keyGen-encaps failed.", "ML-KEM self tests failed"}},
      {"ML-KEM-encapsulate-ciphertext", kMLKEM,
       {"ML-KEM-encapsulate-ciphertext failed.", "ML-KEM self tests failed"}},
      {"ML-KEM-encapsulate-shared-secret", kMLKEM,
       {"ML-KEM-encapsulate-shared-secret failed.",
        "ML-KEM self tests failed"}},
      {"ML-KEM-decapsulate-non-rejection", kMLKEM,
       {"ML-KEM-decapsulate-non-rejection failed.",
        "ML-KEM self tests failed"}},
      {"ML-KEM-decapsulate-rejection", kMLKEM,
       {"ML-KEM-decapsulate-rejection failed.", "ML-KEM self tests failed"}},
      {"ML-DSA-keyGen", kMLDSA,
       {"ML-DSA-keyGen failed.", "ML-DSA self tests failed"}},
      {"ML-DSA-sign", kMLDSA,
       {"ML-DSA-sign failed.", "ML-DSA self tests failed"}},
      {"ML-DSA-verify", kMLDSA,
       {"ML-DSA-verify failed", "ML-DSA self tests failed"}},
  };
  return kTests;
}

const BrokenTest *ExpectedBrokenTest() {
  const char *name = getenv("FIPS_CALLBACK_TEST_EXPECTED_FAILURE");
  if (name == nullptr) {
    return nullptr;
  }
  for (const BrokenTest &test : BrokenTests()) {
    if (strcmp(test.name, name) == 0) {
      return &test;
    }
  }
  ADD_FAILURE() << "Unknown FIPS_CALLBACK_TEST_EXPECTED_FAILURE: " << name;
  return nullptr;
}

bool LastErrorIsModuleErrorState() {
  const uint32_t err = ERR_peek_last_error();
  return ERR_GET_LIB(err) == ERR_LIB_CRYPTO &&
         ERR_GET_REASON(err) == ERR_R_FIPS_MODULE_ERROR_STATE;
}

// Operations, one per algorithm group. Each returns true on success. They are
// the operations that trigger the group's lazy KAT and, where applicable, its
// pairwise consistency test.

bool GenerateRSA() {
  bssl::UniquePtr<RSA> rsa(RSA_new());
  return rsa && RSA_generate_key_fips(rsa.get(), 2048, nullptr);
}

bool GenerateEC() {
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  return key && EC_KEY_generate_key_fips(key.get());
}

bool GenerateFFDH() {
  // Use a fixed group rather than |DH_generate_parameters_ex|, which draws
  // randomness through |BN_rand| without passing a self-test gate first.
  bssl::UniquePtr<DH> dh(DH_get_rfc7919_2048());
  return dh && DH_generate_key(dh.get());
}

bool GenerateWithEVP(int pkey_id, int nid) {
  bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(pkey_id, nullptr));
  if (!ctx) {
    return false;
  }
  if (pkey_id == EVP_PKEY_KEM && !EVP_PKEY_CTX_kem_set_params(ctx.get(), nid)) {
    return false;
  }
  if (pkey_id == EVP_PKEY_PQDSA &&
      !EVP_PKEY_CTX_pqdsa_set_params(ctx.get(), nid)) {
    return false;
  }
  if (!EVP_PKEY_keygen_init(ctx.get())) {
    return false;
  }
  EVP_PKEY *raw = nullptr;
  const bool ok = EVP_PKEY_keygen(ctx.get(), &raw);
  EVP_PKEY_free(raw);
  return ok;
}

bool GenerateMLKEM() { return GenerateWithEVP(EVP_PKEY_KEM, NID_MLKEM512); }
bool GenerateMLDSA() { return GenerateWithEVP(EVP_PKEY_PQDSA, NID_MLDSA44); }
bool GenerateEd25519() { return GenerateWithEVP(EVP_PKEY_ED25519, 0); }

bool SignEd25519ph() {
  // Signing only needs private key bytes, so a fixed key avoids depending on
  // Ed25519 key generation, which belongs to a different group.
  static const uint8_t kPrivateKey[ED25519_PRIVATE_KEY_LEN] = {1};
  static const uint8_t kMessage[2] = {0};
  uint8_t signature[ED25519_SIGNATURE_LEN];
  return ED25519ph_sign(signature, kMessage, sizeof(kMessage), kPrivateKey,
                        nullptr, 0);
}

struct Operation {
  const char *name;
  Group group;
  bool (*run)();
};

const Operation kOperations[] = {
    {"RSA keygen", kRSA, GenerateRSA},
    {"EC keygen", kECC, GenerateEC},
    {"FFDH keygen", kFFDH, GenerateFFDH},
    {"ML-KEM keygen", kMLKEM, GenerateMLKEM},
    {"Ed25519 keygen", kEdDSA, GenerateEd25519},
    {"Ed25519ph sign", kEdDSAph, SignEd25519ph},
    {"ML-DSA keygen", kMLDSA, GenerateMLDSA},
};

// RunOperations runs every operation once. An operation is expected to succeed
// unless the module is already in the error state or it belongs to the group
// whose test is broken, in which case it is the operation that must fail and
// put the module into the error state.
void RunOperations(const BrokenTest *broken) {
  for (const Operation &op : kOperations) {
    SCOPED_TRACE(op.name);
    const bool already_failed = AWS_LC_fips_failure_detected();
    const bool expect_ok =
        !already_failed && (broken == nullptr || broken->group != op.group);
    ERR_clear_error();
    EXPECT_EQ(expect_ok, op.run());
    if (!expect_ok) {
      EXPECT_TRUE(AWS_LC_fips_failure_detected());
      if (already_failed) {
        // Rejected by the gate before doing any work.
        EXPECT_TRUE(LastErrorIsModuleErrorState());
      }
    }
  }
}

// ServiceIndicatorAdvances reports whether an approved service (a SHA-256
// digest) is still reported as approved.
bool ServiceIndicatorAdvances() {
  const uint8_t kInput[1] = {0};
  uint8_t digest[SHA256_DIGEST_LENGTH];
  const uint64_t before = FIPS_service_indicator_before_call();
  SHA256(kInput, sizeof(kInput), digest);
  const uint64_t after = FIPS_service_indicator_after_call();
  return before != after;
}

}  // namespace

TEST(FIPSCallback, ExpectedFailure) {
  const char *name = getenv("FIPS_CALLBACK_TEST_EXPECTED_FAILURE");
  SCOPED_TRACE(name == nullptr ? "(no broken test)" : name);
  const BrokenTest *broken = ExpectedBrokenTest();

  if (broken == nullptr) {
    // Healthy module: nothing has failed yet.
    EXPECT_EQ(0, callback_call_count);
    EXPECT_EQ(0, AWS_LC_fips_failure_detected());
  } else if (broken->group == kStartup) {
    // The module constructor already reported the failure.
    EXPECT_EQ(1, AWS_LC_fips_failure_detected());
    EXPECT_EQ((int)broken->messages.size(), callback_call_count);
  } else {
    // Lazy KATs and PCTs only fire once the algorithm is used.
    EXPECT_EQ(0, callback_call_count);
    EXPECT_EQ(0, AWS_LC_fips_failure_detected());
  }

  RunOperations(broken);

  if (broken == nullptr) {
    EXPECT_EQ(0, callback_call_count);
    EXPECT_EQ(0, AWS_LC_fips_failure_detected());
#if defined(BORINGSSL_FIPS)
    EXPECT_TRUE(ServiceIndicatorAdvances());
#if !defined(OPENSSL_ASAN) && !defined(OPENSSL_MSAN)
    EXPECT_EQ(1, FIPS_mode());
#endif
#endif
    uint8_t buf[16];
    EXPECT_TRUE(RAND_bytes(buf, sizeof(buf)));
    return;
  }

  // The callback was invoked exactly once per failing test, with the expected
  // message, and the process is still running.
  ASSERT_EQ((int)broken->messages.size(), callback_call_count);
  for (size_t i = 0; i < broken->messages.size(); i++) {
    EXPECT_STREQ(broken->messages[i], callback_messages[i]) << "message " << i;
  }

  // The module is now in the error state and advertises it.
  EXPECT_EQ(1, AWS_LC_fips_failure_detected());
  EXPECT_EQ(0, FIPS_mode());

  // No service may be reported as approved any more.
  EXPECT_FALSE(ServiceIndicatorAdvances());

  // The DRBG refuses to produce output.
  uint8_t buf[16];
  ERR_clear_error();
  EXPECT_FALSE(RAND_bytes(buf, sizeof(buf)));
  EXPECT_TRUE(LastErrorIsModuleErrorState());
  ERR_clear_error();
  EXPECT_FALSE(RAND_public_bytes(buf, sizeof(buf)));
  EXPECT_TRUE(LastErrorIsModuleErrorState());

  // Signing is rejected by the gate, whatever key is supplied, and the gate
  // is what fails rather than the (empty) key.
  bssl::UniquePtr<RSA> rsa(RSA_new());
  ASSERT_TRUE(rsa);
  uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
  uint8_t sig[512];
  unsigned sig_len = 0;
  ERR_clear_error();
  EXPECT_FALSE(RSA_sign(NID_sha256, digest, sizeof(digest), sig, &sig_len,
                        rsa.get()));
  EXPECT_TRUE(LastErrorIsModuleErrorState());

  bssl::UniquePtr<EC_KEY> ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  ASSERT_TRUE(ec);
  ERR_clear_error();
  EXPECT_FALSE(ECDSA_do_sign(digest, sizeof(digest), ec.get()));
  EXPECT_TRUE(LastErrorIsModuleErrorState());

  // Every operation now fails up front without re-running any KAT or invoking
  // the callback again.
  const int count_before = callback_call_count;
  RunOperations(broken);
  EXPECT_EQ(count_before, callback_call_count);

  // The on-demand self-test is refused as well: the module is already known to
  // have failed, and the KATs must not run (some draw randomness).
  EXPECT_FALSE(BORINGSSL_self_test());
  EXPECT_EQ(count_before, callback_call_count);
  EXPECT_EQ(1, AWS_LC_fips_failure_detected());
}
