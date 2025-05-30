/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <algorithm>
#include <array>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/aead.h>
#include <openssl/base64.h>
#include <openssl/bio.h>
#include <openssl/bytestring.h>
#include <openssl/cipher.h>
#include <openssl/crypto.h>
#include <openssl/curve25519.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/hpke.h>
#include <openssl/hrss.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "../crypto/internal.h"
#include "../crypto/test/file_util.h"
#include "../crypto/test/test_util.h"
#include "internal.h"
#include "../crypto/kyber/kem_kyber.h"
#include "../crypto/fipsmodule/ec/internal.h"
#include "../crypto/fipsmodule/ml_kem/ml_kem.h"

#if defined(OPENSSL_WINDOWS)
// Windows defines struct timeval in winsock2.h.
OPENSSL_MSVC_PRAGMA(warning(push, 3))
#include <winsock2.h>
OPENSSL_MSVC_PRAGMA(warning(pop))
#else
#include <sys/time.h>
#endif

#if defined(OPENSSL_THREADS)
#include <thread>
#endif

BSSL_NAMESPACE_BEGIN

namespace {

#define TRACED_CALL(code)                     \
  do {                                        \
    SCOPED_TRACE("<- called from here");      \
    code;                                     \
    if (::testing::Test::HasFatalFailure()) { \
      return;                                 \
    }                                         \
  } while (false)

struct VersionParam {
  uint16_t version;
  enum { is_tls, is_dtls } ssl_method;
  // This field is used to generate custom test name suffixes
  // based on the test parameters.
  const char name[20];
  // SSL transfer: the sever SSL is encoded into bytes, and then decoded to
  // another SSL. After transfer, the encoded SSL is freed. The decoded one is
  // used to exchange data. This flag is to replay existing tests with the
  // transferred SSL. If false, the tests use the original server SSL. If true,
  // the tests are replayed with the transferred server SSL. Note: SSL transfer
  // works only with either TLS 1.2 or TLS 1.3 after handshake finished and all
  // post-handshake messages have been flushed.
  bool transfer_ssl;
};

struct SSLTestParam {
  // SSL transfer: the sever SSL is encoded into bytes, and then decoded to
  // another SSL. After transfer, the encoded SSL is freed. The decoded one is
  // used to exchange data. This flag is to replay existing tests with the
  // transferred SSL. If false, the tests use the original server SSL. If true,
  // the tests are replayed with the transferred server SSL. Note: SSL transfer
  // works only with either TLS 1.2 or TLS 1.3 after handshake finished and all
  // post-handshake messages have been flushed.
  bool transfer_ssl;
};

static const size_t kTicketKeyLen = 48;

// If true, after handshake finished, the test uses the transferred SSL.
static const bool TRANSFER_SSL = true;

static const VersionParam kAllVersions[] = {
    {TLS1_VERSION, VersionParam::is_tls, "TLS1", !TRANSFER_SSL},
    {TLS1_1_VERSION, VersionParam::is_tls, "TLS1_1", !TRANSFER_SSL},
    {TLS1_2_VERSION, VersionParam::is_tls, "TLS1_2", !TRANSFER_SSL},
    {TLS1_3_VERSION, VersionParam::is_tls, "TLS1_3", !TRANSFER_SSL},
    {DTLS1_VERSION, VersionParam::is_dtls, "DTLS1", !TRANSFER_SSL},
    {DTLS1_2_VERSION, VersionParam::is_dtls, "DTLS1_2", !TRANSFER_SSL},
    {TLS1_2_VERSION, VersionParam::is_tls, "TLS1_2_SSL_TRANSFER", TRANSFER_SSL},
    {TLS1_3_VERSION, VersionParam::is_tls, "TLS1_3_SSL_TRANSFER", TRANSFER_SSL},
};

static const SSLTestParam kSSLTestParams[] = {
    {!TRANSFER_SSL},
    {TRANSFER_SSL},
};

class SSLTest : public testing::TestWithParam<SSLTestParam> {};

INSTANTIATE_TEST_SUITE_P(SSLTests, SSLTest, testing::ValuesIn(kSSLTestParams),
                         [](const testing::TestParamInfo<SSLTestParam> &i) {
                           if (i.param.transfer_ssl) {
                             return "SSL_Transfer";
                           } else {
                             return "NO_SSL_Transfer";
                           }
                         });

struct ExpectedCipher {
  unsigned long id;
  int in_group_flag;
};

struct CipherTest {
  // The rule string to apply.
  const char *rule;
  // The list of expected ciphers, in order.
  std::vector<ExpectedCipher> expected;
  // True if this cipher list should fail in strict mode.
  bool strict_fail;
};

struct CurveTest {
  // The rule string to apply.
  const char *rule;
  // The list of expected curves, in order.
  std::vector<uint16_t> expected;
};

struct GroupTest {
  int nid;
  uint16_t group_id;
  size_t offer_key_share_size;
  size_t accept_key_share_size;
  size_t shared_secret_size;
};

struct HybridGroupTest {
  int nid;
  uint16_t group_id;
  size_t offer_key_share_size;
  size_t accept_key_share_size;
  size_t shared_secret_size;
  size_t offer_share_sizes[NUM_HYBRID_COMPONENTS];
  size_t accept_share_sizes[NUM_HYBRID_COMPONENTS];
};

struct HybridHandshakeTest {
  // The curves rule string to apply to the client
  const char *client_rule;
  // TLS version that the client is configured with
  uint16_t client_version;
  // The curves rule string to apply to the server
  const char *server_rule;
  // TLS version that the server is configured with
  uint16_t server_version;
  // The group that is expected to be negotiated
  uint16_t expected_group;
  // Is a HelloRetryRequest expected?
  bool is_hrr_expected;
};

template <typename T>
class UnownedSSLExData {
 public:
  UnownedSSLExData() {
    index_ = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  }

  T *Get(const SSL *ssl) {
    return index_ < 0 ? nullptr
                      : static_cast<T *>(SSL_get_ex_data(ssl, index_));
  }

  bool Set(SSL *ssl, T *t) {
    return index_ >= 0 && SSL_set_ex_data(ssl, index_, t);
  }

 private:
  int index_;
};

static const CipherTest kCipherTests[] = {
    // Selecting individual ciphers should work.
    {
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256",
        {
            {TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 0},
            {TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0},
        },
        false,
    },
    // + reorders selected ciphers to the end, keeping their relative order.
    {
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "+aRSA",
        {
            {TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 0},
            {TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0},
        },
        false,
    },
    // ! banishes ciphers from future selections.
    {
        "!aRSA:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256",
        {
            {TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 0},
            {TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0},
        },
        false,
    },
    // Multiple masks can be ANDed in a single rule.
    {
        "kRSA+AESGCM+AES128",
        {
            {TLS1_CK_RSA_WITH_AES_128_GCM_SHA256, 0},
        },
        false,
    },
    // - removes selected ciphers, but preserves their order for future
    // selections. Select AES_128_GCM, but order the key exchanges RSA,
    // ECDHE_RSA.
    {
        "ALL:-kECDHE:"
        "-kRSA:-ALL:"
        "AESGCM+AES128+aRSA",
        {
            {TLS1_CK_RSA_WITH_AES_128_GCM_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0},
        },
        false,
    },
    // Unknown selectors are no-ops, except in strict mode.
    {
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "BOGUS1",
        {
            {TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 0},
            {TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0},
        },
        true,
    },
    // Unknown selectors are no-ops, except in strict mode.
    {
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "-BOGUS2:+BOGUS3:!BOGUS4",
        {
            {TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 0},
            {TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0},
        },
        true,
    },
    // Square brackets specify equi-preference groups.
    {
        "[ECDHE-ECDSA-CHACHA20-POLY1305|ECDHE-ECDSA-AES128-GCM-SHA256]:"
        "[ECDHE-RSA-CHACHA20-POLY1305]:"
        "ECDHE-RSA-AES128-GCM-SHA256",
        {
            {TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 1},
            {TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0},
        },
        false,
    },
    // Standard names may be used instead of OpenSSL names.
    {
        "[TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256|"
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]:"
        "[TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256]:"
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        {
            {TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 1},
            {TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0},
        },
        false,
    },
    // @STRENGTH performs a stable strength-sort of the selected ciphers and
    // only the selected ciphers.
    {
        // To simplify things, banish all but {ECDHE_RSA,RSA} x
        // {CHACHA20,AES_256_CBC,AES_128_CBC} x SHA1.
        "!AESGCM:!3DES:"
        // Order some ciphers backwards by strength.
        "ALL:-CHACHA20:-AES256:-AES128:-ALL:"
        // Select ECDHE ones and sort them by strength. Ties should resolve
        // based on the order above.
        "kECDHE:@STRENGTH:-ALL:"
        // Now bring back everything uses RSA. ECDHE_RSA should be first, sorted
        // by strength. Then RSA, backwards by strength.
        "aRSA",
        {
            {TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384, 0},
            {TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256, 0},
            {TLS1_CK_RSA_WITH_AES_128_SHA, 0},
            {TLS1_CK_RSA_WITH_AES_128_SHA256, 0},
            {TLS1_CK_RSA_WITH_AES_256_SHA, 0},
        },
        false,
    },
    // Additional masks after @STRENGTH get silently discarded.
    //
    // TODO(davidben): Make this an error. If not silently discarded, they get
    // interpreted as + opcodes which are very different.
    {
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "@STRENGTH+AES256",
        {
            {TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0},
        },
        false,
    },
    {
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "@STRENGTH+AES256:"
        "ECDHE-RSA-CHACHA20-POLY1305",
        {
            {TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 0},
        },
        false,
    },
    // Exact ciphers may not be used in multi-part rules; they are treated
    // as unknown aliases.
    {
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "!ECDHE-RSA-AES128-GCM-SHA256+RSA:"
        "!ECDSA+ECDHE-ECDSA-AES128-GCM-SHA256",
        {
            {TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0},
        },
        true,
    },
    // SSLv3 matches everything that existed before TLS 1.2.
    {
        "AES128-SHA:AES128-SHA256:ECDHE-RSA-AES128-GCM-SHA256:!SSLv3",
        {
            {TLS1_CK_RSA_WITH_AES_128_SHA256, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0},
        },
        false,
    },
    // TLSv1.2 matches everything added in TLS 1.2.
    {
        "AES128-SHA:AES128-SHA256:ECDHE-RSA-AES128-GCM-SHA256:!TLSv1.2",
        {
            {TLS1_CK_RSA_WITH_AES_128_SHA, 0},
        },
        false,
    },
    // The two directives have no intersection.  But each component is valid, so
    // even in strict mode it is accepted.
    {
        "AES128-SHA:ECDHE-RSA-AES128-GCM-SHA256:!TLSv1.2+SSLv3",
        {
            {TLS1_CK_RSA_WITH_AES_128_SHA, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0},
        },
        false,
    },
    // Spaces, semi-colons and commas are separators.
    {
        "AES128-SHA: ECDHE-RSA-AES128-GCM-SHA256 AES256-SHA "
        ",ECDHE-ECDSA-AES128-GCM-SHA256 ; AES128-GCM-SHA256",
        {
            {TLS1_CK_RSA_WITH_AES_128_SHA, 0},
            {TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0},
            {TLS1_CK_RSA_WITH_AES_256_SHA, 0},
            {TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0},
            {TLS1_CK_RSA_WITH_AES_128_GCM_SHA256, 0},
        },
        // …but not in strict mode.
        true,
    },
};

// In kTLSv13RuleOnly, |rule| of each CipherTest can only match TLSv1.3 ciphers.
// e.g. kTLSv13RuleOnly does not have rule "AESGCM+AES128", which can match
// some TLSv1.2 ciphers.
static const CipherTest kTLSv13RuleOnly[] = {
    // Selecting individual ciphers should work.
    {
        "TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256:"
        "TLS_AES_128_GCM_SHA256",
        {
            {TLS1_CK_AES_256_GCM_SHA384, 0},
            {TLS1_CK_CHACHA20_POLY1305_SHA256, 0},
            {TLS1_CK_AES_128_GCM_SHA256, 0},
        },
        false,
    },
    // + reorders selected ciphers to the end, keeping their relative order.
    {
        "TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256:"
        "TLS_AES_128_GCM_SHA256:"
        "+AES",
        {
            {TLS1_CK_CHACHA20_POLY1305_SHA256, 0},
            {TLS1_CK_AES_256_GCM_SHA384, 0},
            {TLS1_CK_AES_128_GCM_SHA256, 0},
        },
        false,
    },
    // ! banishes ciphers from future selections.
    {
        "!CHACHA20:"
        "TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256:"
        "TLS_AES_128_GCM_SHA256:"
        "TLS_CHACHA20_POLY1305_SHA256",
        {
            {TLS1_CK_AES_256_GCM_SHA384, 0},
            {TLS1_CK_AES_128_GCM_SHA256, 0},
        },
        false,
    },
    // Square brackets specify equi-preference groups.
    {
        "[TLS_AES_128_GCM_SHA256|TLS_AES_256_GCM_SHA384]:"
        "TLS_CHACHA20_POLY1305_SHA256",
        {
            {TLS1_CK_AES_128_GCM_SHA256, 1},
            {TLS1_CK_AES_256_GCM_SHA384, 0},
            {TLS1_CK_CHACHA20_POLY1305_SHA256, 0},
        },
        false,
    },
    // Spaces, semi-colons and commas are separators.
    {
        "TLS_AES_256_GCM_SHA384 ; "
        "TLS_CHACHA20_POLY1305_SHA256 , "
        "TLS_AES_128_GCM_SHA256",
        {
            {TLS1_CK_AES_256_GCM_SHA384, 0},
            {TLS1_CK_CHACHA20_POLY1305_SHA256, 0},
            {TLS1_CK_AES_128_GCM_SHA256, 0},
        },
        false,
    },
};

// Besides kTLSv13RuleOnly, additional rules can match TLSv1.3 ciphers.
static const CipherTest kTLSv13CipherTests[] = {
    // Multiple masks can be ANDed in a single rule.
    {
        "AESGCM+AES128",
        {
            {TLS1_CK_AES_128_GCM_SHA256, 0},
        },
        false,
    },
    // - removes selected ciphers, but preserves their order for future
    // selections. Select AES_128_GCM, but order the key exchanges RSA,
    // ECDHE_RSA.
    {
        "ALL:-AES",
        {
            {TLS1_CK_CHACHA20_POLY1305_SHA256, 0},
        },
        false,
    },
    // Unknown selectors or TLSv1.2 ciphers are no-ops.
    {
        "TLS_CHACHA20_POLY1305_SHA256:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "BOGUS1",
        {
            {TLS1_CK_CHACHA20_POLY1305_SHA256, 0},
        },
        true,
    },
};

static const char *kBadRules[] = {
  // Invalid brackets.
  "[ECDHE-RSA-CHACHA20-POLY1305|ECDHE-RSA-AES128-GCM-SHA256",
  "RSA]",
  "[[RSA]]",
  // Operators inside brackets.
  "[+RSA]",
  // Unknown directive.
  "@BOGUS",
  "BOGUS",
  // COMPLEMENTOFDEFAULT is empty.
  "COMPLEMENTOFDEFAULT",
  // Invalid command.
  "?BAR",
  // Special operators are not allowed if equi-preference groups are used.
  "[ECDHE-RSA-CHACHA20-POLY1305|ECDHE-RSA-AES128-GCM-SHA256]:+FOO",
  "[ECDHE-RSA-CHACHA20-POLY1305|ECDHE-RSA-AES128-GCM-SHA256]:!FOO",
  "[ECDHE-RSA-CHACHA20-POLY1305|ECDHE-RSA-AES128-GCM-SHA256]:-FOO",
  "[ECDHE-RSA-CHACHA20-POLY1305|ECDHE-RSA-AES128-GCM-SHA256]:@STRENGTH",
  // Opcode supplied, but missing selector.
  "+",
  // Spaces are forbidden in equal-preference groups.
  "[AES128-SHA | AES128-SHA256]",
};

static const char *kMustNotIncludeNull[] = {
    "ALL",  "DEFAULT", "HIGH",  "FIPS",  "SHA",
    "SHA1", "RSA",     "SSLv3", "TLSv1", "TLSv1.2",
};

static const char *kTLSv13MustNotIncludeNull[] = {
    "ALL",
    "DEFAULT",
    "HIGH",
    "FIPS",
};

static const char *kMustNotInclude3DES[] = {
    "ALL", "DEFAULT", "HIGH", "FIPS", "SSLv3", "TLSv1", "TLSv1.2",
};

static const CurveTest kCurveTests[] = {
  {
    "P-256",
    {SSL_GROUP_SECP256R1},
  },
  {
    "P-256:P-384:P-521:X25519",
    {
      SSL_GROUP_SECP256R1,
      SSL_GROUP_SECP384R1,
      SSL_GROUP_SECP521R1,
      SSL_GROUP_X25519,
    },
  },
  {
    "prime256v1:secp384r1:secp521r1:x25519",
    {
      SSL_GROUP_SECP256R1,
      SSL_GROUP_SECP384R1,
      SSL_GROUP_SECP521R1,
      SSL_GROUP_X25519,
    },
  },
  {
    "SecP256r1Kyber768Draft00:prime256v1:secp384r1:secp521r1:x25519",
    {
      SSL_GROUP_SECP256R1_KYBER768_DRAFT00,
      SSL_GROUP_SECP256R1,
      SSL_GROUP_SECP384R1,
      SSL_GROUP_SECP521R1,
      SSL_GROUP_X25519,
    },
  },
  {
    "X25519Kyber768Draft00:prime256v1:secp384r1",
    {
      SSL_GROUP_X25519_KYBER768_DRAFT00,
      SSL_GROUP_SECP256R1,
      SSL_GROUP_SECP384R1,
    },
  },
  {
    "X25519:X25519Kyber768Draft00",
    {
      SSL_GROUP_X25519,
      SSL_GROUP_X25519_KYBER768_DRAFT00,
    },
  },
  {
    "X25519:SecP256r1Kyber768Draft00:prime256v1",
    {
      SSL_GROUP_X25519,
      SSL_GROUP_SECP256R1_KYBER768_DRAFT00,
      SSL_GROUP_SECP256R1,
    },
  },
  {
    "SecP256r1MLKEM768:prime256v1:secp384r1:secp521r1:x25519",
    {
      SSL_GROUP_SECP256R1_MLKEM768,
      SSL_GROUP_SECP256R1,
      SSL_GROUP_SECP384R1,
      SSL_GROUP_SECP521R1,
      SSL_GROUP_X25519,
    },
  },
  {
    "X25519MLKEM768:prime256v1:secp384r1",
    {
      SSL_GROUP_X25519_MLKEM768,
      SSL_GROUP_SECP256R1,
      SSL_GROUP_SECP384R1,
    },
  },
  {
    "X25519:X25519MLKEM768",
    {
      SSL_GROUP_X25519,
      SSL_GROUP_X25519_MLKEM768,
    },
  },
  {
    "X25519:SecP256r1MLKEM768:prime256v1",
    {
      SSL_GROUP_X25519,
      SSL_GROUP_SECP256R1_MLKEM768,
      SSL_GROUP_SECP256R1,
    },
  },
{
  "SecP384r1MLKEM1024:X25519MLKEM768:SecP256r1MLKEM768",
  {
    SSL_GROUP_SECP384R1_MLKEM1024,
    SSL_GROUP_X25519_MLKEM768,
    SSL_GROUP_SECP256R1_MLKEM768,
  },
},
};


// SECP256R1:     https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
// X25519:        https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
static const size_t P256_KEYSHARE_SIZE = ((EC_P256R1_FIELD_ELEM_BYTES * 2) + 1);
static const size_t P256_SECRET_SIZE = EC_P256R1_FIELD_ELEM_BYTES;
static const size_t P384_KEYSHARE_SIZE = ((EC_P384R1_FIELD_ELEM_BYTES * 2) + 1);
static const size_t P384_SECRET_SIZE = EC_P384R1_FIELD_ELEM_BYTES;
static const size_t X25519_KEYSHARE_SIZE = 32;
static const size_t X25519_SECRET_SIZE = 32;

static const GroupTest kKemGroupTests[] = {
  {
    NID_KYBER768_R3,
    SSL_GROUP_KYBER768_R3,
    KYBER768_R3_PUBLIC_KEY_BYTES,
    KYBER768_R3_CIPHERTEXT_BYTES,
    KYBER_R3_SHARED_SECRET_LEN,
  },
  {
    NID_MLKEM768,
    SSL_GROUP_MLKEM768,
    MLKEM768_PUBLIC_KEY_BYTES,
    MLKEM768_CIPHERTEXT_BYTES,
    MLKEM768_SHARED_SECRET_LEN,
  },
};

static const HybridGroupTest kHybridGroupTests[] = {
  {
    NID_SecP256r1Kyber768Draft00,
    SSL_GROUP_SECP256R1_KYBER768_DRAFT00,
    P256_KEYSHARE_SIZE + KYBER768_R3_PUBLIC_KEY_BYTES,
    P256_KEYSHARE_SIZE + KYBER768_R3_CIPHERTEXT_BYTES,
    P256_SECRET_SIZE + KYBER_R3_SHARED_SECRET_LEN,
    {
      P256_KEYSHARE_SIZE,             // offer_share_sizes[0]
      KYBER768_R3_PUBLIC_KEY_BYTES,   // offer_share_sizes[1]
    },
    {
      P256_KEYSHARE_SIZE,             // accept_share_sizes[0]
      KYBER768_R3_CIPHERTEXT_BYTES,   // accept_share_sizes[1]
    },
  },
  {
    NID_X25519Kyber768Draft00,
    SSL_GROUP_X25519_KYBER768_DRAFT00,
    X25519_KEYSHARE_SIZE + KYBER768_R3_PUBLIC_KEY_BYTES,
    X25519_KEYSHARE_SIZE + KYBER768_R3_CIPHERTEXT_BYTES,
    X25519_SECRET_SIZE + KYBER_R3_SHARED_SECRET_LEN,
    {
      X25519_KEYSHARE_SIZE,           // offer_share_sizes[0]
      KYBER768_R3_PUBLIC_KEY_BYTES,   // offer_share_sizes[1]
    },
    {
      X25519_KEYSHARE_SIZE,          // accept_share_sizes[0]
      KYBER768_R3_CIPHERTEXT_BYTES,  // accept_share_sizes[1]
    },
  },
  {
    NID_SecP256r1MLKEM768,
    SSL_GROUP_SECP256R1_MLKEM768,
    P256_KEYSHARE_SIZE + MLKEM768_PUBLIC_KEY_BYTES,
    P256_KEYSHARE_SIZE + MLKEM768_CIPHERTEXT_BYTES,
    P256_SECRET_SIZE + MLKEM768_SHARED_SECRET_LEN,
    {
      P256_KEYSHARE_SIZE,             // offer_share_sizes[0]
      MLKEM768_PUBLIC_KEY_BYTES,      // offer_share_sizes[1]
    },
    {
      P256_KEYSHARE_SIZE,             // accept_share_sizes[0]
      MLKEM768_CIPHERTEXT_BYTES,      // accept_share_sizes[1]
    },
  },
  {
    NID_X25519MLKEM768,
    SSL_GROUP_X25519_MLKEM768,
    X25519_KEYSHARE_SIZE + MLKEM768_PUBLIC_KEY_BYTES,
    X25519_KEYSHARE_SIZE + MLKEM768_CIPHERTEXT_BYTES,
    X25519_SECRET_SIZE + MLKEM768_SHARED_SECRET_LEN,
    {
      // MLKEM768 is sent first for X25519MLKEM768 for FIPS compliance
      // See: https://datatracker.ietf.org/doc/html/draft-kwiatkowski-tls-ecdhe-mlkem.html#section-3
      MLKEM768_PUBLIC_KEY_BYTES,      // offer_share_sizes[0]
      X25519_KEYSHARE_SIZE,           // offer_share_sizes[1]
    },
    {
      // MLKEM768 is sent first for X25519MLKEM768 for FIPS compliance
      // See: https://datatracker.ietf.org/doc/html/draft-kwiatkowski-tls-ecdhe-mlkem.html#section-3
      MLKEM768_CIPHERTEXT_BYTES,      // accept_share_sizes[0]
      X25519_KEYSHARE_SIZE,           // accept_share_sizes[1]
    },
  },
  {
    NID_SecP384r1MLKEM1024,
    SSL_GROUP_SECP384R1_MLKEM1024,
    P384_KEYSHARE_SIZE + MLKEM1024_PUBLIC_KEY_BYTES,
    P384_KEYSHARE_SIZE + MLKEM1024_CIPHERTEXT_BYTES,
    P384_SECRET_SIZE + MLKEM1024_SHARED_SECRET_LEN,
    {
      P384_KEYSHARE_SIZE,             // offer_share_sizes[0]
      MLKEM1024_PUBLIC_KEY_BYTES,     // offer_share_sizes[1]
    },
    {
      P384_KEYSHARE_SIZE,             // accept_share_sizes[0]
      MLKEM1024_CIPHERTEXT_BYTES,     // accept_share_sizes[1]
    },
  },
};

static const char *kBadCurvesLists[] = {
  "",
  ":",
  "::",
  "P-256::X25519",
  "RSA:P-256",
  "P-256:RSA",
  "X25519:P-256:",
  ":X25519:P-256",
  "kyber768_r3",
  "x25519_kyber768:prime256v1",
  "mlkem768",
  "x25519_mlkem768:prime256v1",
};

static const HybridHandshakeTest kHybridHandshakeTests[] = {
  // The corresponding hybrid group should be negotiated when client
  // and server support only that group
  {
    "X25519Kyber768Draft00",
    TLS1_3_VERSION,
    "X25519Kyber768Draft00",
    TLS1_3_VERSION,
    SSL_GROUP_X25519_KYBER768_DRAFT00,
    false,
  },

  {
    "SecP256r1Kyber768Draft00",
    TLS1_3_VERSION,
    "SecP256r1Kyber768Draft00",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1_KYBER768_DRAFT00,
    false,
  },

  // The client's preferred hybrid group should be negotiated when also
  // supported by the server, even if the server "prefers"/supports other groups.
  {
    "X25519Kyber768Draft00:x25519",
    TLS1_3_VERSION,
    "x25519:prime256v1:X25519Kyber768Draft00",
    TLS1_3_VERSION,
    SSL_GROUP_X25519_KYBER768_DRAFT00,
    false,
  },

  {
    "X25519Kyber768Draft00:x25519",
    TLS1_3_VERSION,
    "X25519Kyber768Draft00:x25519",
    TLS1_3_VERSION,
    SSL_GROUP_X25519_KYBER768_DRAFT00,
    false,
  },

  {
    "SecP256r1Kyber768Draft00",
    TLS1_3_VERSION,
    "X25519Kyber768Draft00:secp384r1:x25519:SecP256r1Kyber768Draft00",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1_KYBER768_DRAFT00,
    false,
  },

  // The client lists PQ/hybrid groups as both first and second preferences.
  // The key share logic is implemented such that the client will always
  // attempt to send one hybrid key share and one classical key share.
  // Therefore, the client will send key shares [SecP256r1Kyber768Draft00, x25519],
  // skipping X25519Kyber768Draft00, and the server will choose to negotiate
  // x25519 since it is the only mutually supported group.
  {
    "SecP256r1Kyber768Draft00:X25519Kyber768Draft00:x25519",
    TLS1_3_VERSION,
    "secp384r1:x25519",
    TLS1_3_VERSION,
    SSL_GROUP_X25519,
    false,
  },

  // The client will send key shares [x25519, SecP256r1Kyber768Draft00].
  // The server will negotiate SecP256r1Kyber768Draft00 since it is the only
  // mutually supported group.
  {
    "x25519:secp384r1:SecP256r1Kyber768Draft00",
    TLS1_3_VERSION,
    "SecP256r1Kyber768Draft00:prime256v1",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1_KYBER768_DRAFT00,
    false,
  },

  // The client will send key shares [x25519, SecP256r1Kyber768Draft00]. The
  // server will negotiate x25519 since the client listed it as its first
  // preference, even though it supports SecP256r1Kyber768Draft00.
  {
    "x25519:prime256v1:SecP256r1Kyber768Draft00",
    TLS1_3_VERSION,
    "prime256v1:x25519:SecP256r1Kyber768Draft00",
    TLS1_3_VERSION,
    SSL_GROUP_X25519,
    false,
  },

  // The client will send key shares [SecP256r1Kyber768Draft00, x25519].
  // The server will negotiate SecP256r1Kyber768Draft00 since the client listed
  // it as its first preference.
  {
    "SecP256r1Kyber768Draft00:x25519:prime256v1",
    TLS1_3_VERSION,
    "prime256v1:x25519:SecP256r1Kyber768Draft00",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1_KYBER768_DRAFT00,
    false,
  },

  // In the supported_groups extension, the client will indicate its
  // preferences, in order, as [SecP256r1Kyber768Draft00, X25519Kyber768Draft00,
  // x25519, prime256v1]. From those groups, it will send key shares
  // [SecP256r1Kyber768Draft00, x25519]. The server supports, and receives a
  // key share for, x25519. However, when selecting a mutually supported group
  // to negotiate, the server recognizes that the client prefers
  // X25519Kyber768Draft00 over x25519. Since the server also supports
  // X25519Kyber768Draft00, but did not receive a key share for it, it will
  // select it and send an HRR. This ensures that the client's highest
  // preference group will be negotiated, even at the expense of an additional
  // round-trip.
  //
  // In our SSL implementation, this situation is unique to the case where the
  // client supports both ECC and hybrid/PQ. When sending key shares, the
  // client will send at most two key shares in one of the following ways:

  // (a) one ECC key share - if the client supports only ECC;
  // (b) one PQ key share - if the client supports only PQ;
  // (c) one ECC and one PQ key share - if the client supports ECC and PQ.
  //
  // One of the above cases will be true irrespective of how many groups
  // the client supports. If, say, the client supports four ECC groups
  // and zero PQ groups, it will still only send a single ECC share. In cases
  // (a) and (b), either the server supports that group and chooses to
  // negotiate it, or it doesn't support it and sends an HRR. Case (c) is the
  // only case where the server might receive a key share for a mutually
  // supported group, but chooses to respect the client's preference order
  // defined in the supported_groups extension at the expense of an additional
  // round-trip.
  {
    "SecP256r1Kyber768Draft00:X25519Kyber768Draft00:x25519:prime256v1",
    TLS1_3_VERSION,
    "X25519Kyber768Draft00:prime256v1:x25519",
    TLS1_3_VERSION,
    SSL_GROUP_X25519_KYBER768_DRAFT00,
    true,
  },

  // Like the previous case, but the client's prioritization of ECC and PQ
  // is inverted.
  {
    "x25519:prime256v1:SecP256r1Kyber768Draft00:X25519Kyber768Draft00",
    TLS1_3_VERSION,
    "X25519Kyber768Draft00:prime256v1",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1,
    true,
  },

  // The client will send key shares [SecP256r1Kyber768Draft00, x25519]. The
  // server will negotiate X25519Kyber768Draft00 after an HRR.
  {
    "SecP256r1Kyber768Draft00:X25519Kyber768Draft00:x25519:prime256v1",
    TLS1_3_VERSION,
    "X25519Kyber768Draft00:prime256v1",
    TLS1_3_VERSION,
    SSL_GROUP_X25519_KYBER768_DRAFT00,
    true,
  },

  // EC should be negotiated when client prefers EC, or server does not
  // support hybrid
  {
    "X25519Kyber768Draft00:x25519",
    TLS1_3_VERSION,
    "x25519",
    TLS1_3_VERSION,
    SSL_GROUP_X25519,
    false,
  },
  {
    "x25519:SecP256r1Kyber768Draft00",
    TLS1_3_VERSION,
    "x25519",
    TLS1_3_VERSION,
    SSL_GROUP_X25519,
    false,
  },
  {
    "prime256v1:X25519Kyber768Draft00",
    TLS1_3_VERSION,
    "X25519Kyber768Draft00:prime256v1",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1,
    false,
  },
  {
    "prime256v1:x25519:SecP256r1Kyber768Draft00",
    TLS1_3_VERSION,
    "x25519:prime256v1:SecP256r1Kyber768Draft00",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1,
    false,
  },

  // EC should be negotiated, after a HelloRetryRequest, if the server
  // supports only curves for which it did not initially receive a key share
  {
    "X25519Kyber768Draft00:x25519:SecP256r1Kyber768Draft00:prime256v1",
    TLS1_3_VERSION,
    "prime256v1",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1,
    true,
  },
  {
    "X25519Kyber768Draft00:SecP256r1Kyber768Draft00:prime256v1:x25519",
    TLS1_3_VERSION,
    "secp224r1:secp384r1:secp521r1:x25519",
    TLS1_3_VERSION,
    SSL_GROUP_X25519,
    true,
  },

  // Hybrid should be negotiated, after a HelloRetryRequest, if the server
  // supports only curves for which it did not initially receive a key share
  {
    "x25519:prime256v1:SecP256r1Kyber768Draft00:X25519Kyber768Draft00",
    TLS1_3_VERSION,
    "secp224r1:X25519Kyber768Draft00:secp521r1",
    TLS1_3_VERSION,
    SSL_GROUP_X25519_KYBER768_DRAFT00,
    true,
  },
  {
    "X25519Kyber768Draft00:x25519:prime256v1:SecP256r1Kyber768Draft00",
    TLS1_3_VERSION,
    "SecP256r1Kyber768Draft00",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1_KYBER768_DRAFT00,
    true,
  },

  // If there is no overlap between client and server groups,
  // the handshake should fail
  {
    "SecP256r1Kyber768Draft00:X25519Kyber768Draft00:secp384r1",
    TLS1_3_VERSION,
    "prime256v1:x25519",
    TLS1_3_VERSION,
    0,
    false,
  },
  {
    "secp384r1:SecP256r1Kyber768Draft00:X25519Kyber768Draft00",
    TLS1_3_VERSION,
    "prime256v1:x25519",
    TLS1_3_VERSION,
    0,
    false,
  },
  {
    "secp384r1:SecP256r1Kyber768Draft00",
    TLS1_3_VERSION,
    "prime256v1:x25519:X25519Kyber768Draft00",
    TLS1_3_VERSION,
    0,
    false,
  },
  {
    "SecP256r1Kyber768Draft00",
    TLS1_3_VERSION,
    "X25519Kyber768Draft00",
    TLS1_3_VERSION,
    0,
    false,
  },

  // If the client supports hybrid TLS 1.3, but the server
  // only supports TLS 1.2, then TLS 1.2 EC should be negotiated.
  {
    "SecP256r1Kyber768Draft00:prime256v1",
    TLS1_3_VERSION,
    "prime256v1:x25519",
    TLS1_2_VERSION,
    SSL_GROUP_SECP256R1,
    false,
  },

  // Same as above, but server also has SecP256r1Kyber768Draft00 in it's
  // supported list, but can't use it since TLS 1.3 is the minimum version that
  // supports PQ.
  {
    "SecP256r1Kyber768Draft00:prime256v1",
    TLS1_3_VERSION,
    "SecP256r1Kyber768Draft00:prime256v1:x25519",
    TLS1_2_VERSION,
    SSL_GROUP_SECP256R1,
    false,
  },

  // If the client configures the curve list to include a hybrid
  // curve, then initiates a 1.2 handshake, it will not advertise
  // hybrid groups because hybrid is not supported for 1.2. So
  // a 1.2 EC handshake will be negotiated (even if the server
  // supports 1.3 with corresponding hybrid group).
  {
    "SecP256r1Kyber768Draft00:x25519",
    TLS1_2_VERSION,
    "SecP256r1Kyber768Draft00:x25519",
    TLS1_3_VERSION,
    SSL_GROUP_X25519,
    false,
  },
  {
    "SecP256r1Kyber768Draft00:prime256v1",
    TLS1_2_VERSION,
    "prime256v1:x25519",
    TLS1_2_VERSION,
    SSL_GROUP_SECP256R1,
    false,
  },
  // The corresponding hybrid group should be negotiated when client
  // and server support only that group
  {
    "X25519MLKEM768",
    TLS1_3_VERSION,
    "X25519MLKEM768",
    TLS1_3_VERSION,
    SSL_GROUP_X25519_MLKEM768,
    false,
  },

  {
    "SecP256r1MLKEM768",
    TLS1_3_VERSION,
    "SecP256r1MLKEM768",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1_MLKEM768,
    false,
  },

  {
    "SecP384r1MLKEM1024",
    TLS1_3_VERSION,
    "SecP384r1MLKEM1024",
    TLS1_3_VERSION,
    SSL_GROUP_SECP384R1_MLKEM1024,
    false,
  },

  // The client's preferred hybrid group should be negotiated when also
  // supported by the server, even if the server "prefers"/supports other groups.
  {
    "X25519MLKEM768:x25519",
    TLS1_3_VERSION,
    "x25519:prime256v1:X25519MLKEM768",
    TLS1_3_VERSION,
    SSL_GROUP_X25519_MLKEM768,
    false,
  },

  {
    "X25519MLKEM768:x25519",
    TLS1_3_VERSION,
    "X25519MLKEM768:x25519",
    TLS1_3_VERSION,
    SSL_GROUP_X25519_MLKEM768,
    false,
  },

  {
    "SecP256r1MLKEM768",
    TLS1_3_VERSION,
    "X25519MLKEM768:secp384r1:x25519:SecP256r1MLKEM768",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1_MLKEM768,
    false,
  },

  {
    "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024",
    TLS1_3_VERSION,
    "SecP384r1MLKEM1024:SecP256r1MLKEM768:X25519MLKEM768",
    TLS1_3_VERSION,
    SSL_GROUP_X25519_MLKEM768,
    false,
  },

  {
    "SecP384r1MLKEM1024:SecP256r1MLKEM768:X25519MLKEM768",
    TLS1_3_VERSION,
    "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024",
    TLS1_3_VERSION,
    SSL_GROUP_SECP384R1_MLKEM1024,
    false,
  },

  // The client lists PQ/hybrid groups as both first and second preferences.
  // The key share logic is implemented such that the client will always
  // attempt to send one hybrid key share and one classical key share.
  // Therefore, the client will send key shares [SecP256r1MLKEM768, x25519],
  // skipping X25519MLKEM768, and the server will choose to negotiate
  // x25519 since it is the only mutually supported group.
  {
    "SecP256r1MLKEM768:X25519MLKEM768:x25519",
    TLS1_3_VERSION,
    "secp384r1:x25519",
    TLS1_3_VERSION,
    SSL_GROUP_X25519,
    false,
  },

  // The client will send key shares [x25519, SecP256r1MLKEM768].
  // The server will negotiate SecP256r1MLKEM768 since it is the only
  // mutually supported group.
  {
    "x25519:secp384r1:SecP256r1MLKEM768",
    TLS1_3_VERSION,
    "SecP256r1MLKEM768:prime256v1",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1_MLKEM768,
    false,
  },

  // The client will send key shares [x25519, SecP256r1MLKEM768]. The
  // server will negotiate x25519 since the client listed it as its first
  // preference, even though it supports SecP256r1MLKEM768.
  {
    "x25519:prime256v1:SecP256r1MLKEM768",
    TLS1_3_VERSION,
    "prime256v1:x25519:SecP256r1MLKEM768",
    TLS1_3_VERSION,
    SSL_GROUP_X25519,
    false,
  },

  // The client will send key shares [SecP256r1MLKEM768, x25519].
  // The server will negotiate SecP256r1MLKEM768 since the client listed
  // it as its first preference.
  {
    "SecP256r1MLKEM768:x25519:prime256v1",
    TLS1_3_VERSION,
    "prime256v1:x25519:SecP256r1MLKEM768",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1_MLKEM768,
    false,
  },

  // In the supported_groups extension, the client will indicate its
  // preferences, in order, as [SecP256r1MLKEM768, X25519MLKEM768,
  // x25519, prime256v1]. From those groups, it will send key shares
  // [SecP256r1MLKEM768, x25519]. The server supports, and receives a
  // key share for, x25519. However, when selecting a mutually supported group
  // to negotiate, the server recognizes that the client prefers
  // X25519MLKEM768 over x25519. Since the server also supports
  // X25519MLKEM768, but did not receive a key share for it, it will
  // select it and send an HRR. This ensures that the client's highest
  // preference group will be negotiated, even at the expense of an additional
  // round-trip.
  //
  // In our SSL implementation, this situation is unique to the case where the
  // client supports both ECC and hybrid/PQ. When sending key shares, the
  // client will send at most two key shares in one of the following ways:

  // (a) one ECC key share - if the client supports only ECC;
  // (b) one PQ key share - if the client supports only PQ;
  // (c) one ECC and one PQ key share - if the client supports ECC and PQ.
  //
  // One of the above cases will be true irrespective of how many groups
  // the client supports. If, say, the client supports four ECC groups
  // and zero PQ groups, it will still only send a single ECC share. In cases
  // (a) and (b), either the server supports that group and chooses to
  // negotiate it, or it doesn't support it and sends an HRR. Case (c) is the
  // only case where the server might receive a key share for a mutually
  // supported group, but chooses to respect the client's preference order
  // defined in the supported_groups extension at the expense of an additional
  // round-trip.
  {
    "SecP256r1MLKEM768:X25519MLKEM768:x25519:prime256v1",
    TLS1_3_VERSION,
    "X25519MLKEM768:prime256v1:x25519",
    TLS1_3_VERSION,
    SSL_GROUP_X25519_MLKEM768,
    true,
  },

  // Like the previous case, but the client's prioritization of ECC and PQ
  // is inverted.
  {
    "x25519:prime256v1:SecP256r1MLKEM768:X25519MLKEM768",
    TLS1_3_VERSION,
    "X25519MLKEM768:prime256v1",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1,
    true,
  },

  // The client will send key shares [SecP256r1MLKEM768, x25519]. The
  // server will negotiate X25519MLKEM768 after an HRR.
  {
    "SecP256r1MLKEM768:X25519MLKEM768:x25519:prime256v1",
    TLS1_3_VERSION,
    "X25519MLKEM768:prime256v1",
    TLS1_3_VERSION,
    SSL_GROUP_X25519_MLKEM768,
    true,
  },

  // EC should be negotiated when client prefers EC, or server does not
  // support hybrid
  {
    "X25519MLKEM768:x25519",
    TLS1_3_VERSION,
    "x25519",
    TLS1_3_VERSION,
    SSL_GROUP_X25519,
    false,
  },
  {
    "x25519:SecP256r1MLKEM768",
    TLS1_3_VERSION,
    "x25519",
    TLS1_3_VERSION,
    SSL_GROUP_X25519,
    false,
  },
  {
    "prime256v1:X25519MLKEM768",
    TLS1_3_VERSION,
    "X25519MLKEM768:prime256v1",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1,
    false,
  },
  {
    "prime256v1:x25519:SecP256r1MLKEM768",
    TLS1_3_VERSION,
    "x25519:prime256v1:SecP256r1MLKEM768",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1,
    false,
  },

  // EC should be negotiated, after a HelloRetryRequest, if the server
  // supports only curves for which it did not initially receive a key share
  {
    "X25519MLKEM768:x25519:SecP256r1MLKEM768:prime256v1",
    TLS1_3_VERSION,
    "prime256v1",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1,
    true,
  },
  {
    "X25519MLKEM768:SecP256r1MLKEM768:prime256v1:x25519",
    TLS1_3_VERSION,
    "secp224r1:secp384r1:secp521r1:x25519",
    TLS1_3_VERSION,
    SSL_GROUP_X25519,
    true,
  },

  // Hybrid should be negotiated, after a HelloRetryRequest, if the server
  // supports only curves for which it did not initially receive a key share
  {
    "x25519:prime256v1:SecP256r1MLKEM768:X25519MLKEM768",
    TLS1_3_VERSION,
    "secp224r1:X25519MLKEM768:secp521r1",
    TLS1_3_VERSION,
    SSL_GROUP_X25519_MLKEM768,
    true,
  },
  {
    "X25519MLKEM768:x25519:prime256v1:SecP256r1MLKEM768",
    TLS1_3_VERSION,
    "SecP256r1MLKEM768",
    TLS1_3_VERSION,
    SSL_GROUP_SECP256R1_MLKEM768,
    true,
  },

  // If there is no overlap between client and server groups,
  // the handshake should fail
  {
    "SecP256r1MLKEM768:X25519MLKEM768:secp384r1",
    TLS1_3_VERSION,
    "prime256v1:x25519",
    TLS1_3_VERSION,
    0,
    false,
  },
  {
    "secp384r1:SecP256r1MLKEM768:X25519MLKEM768",
    TLS1_3_VERSION,
    "prime256v1:x25519",
    TLS1_3_VERSION,
    0,
    false,
  },
  {
    "secp384r1:SecP256r1MLKEM768",
    TLS1_3_VERSION,
    "prime256v1:x25519:X25519MLKEM768",
    TLS1_3_VERSION,
    0,
    false,
  },
  {
    "SecP256r1MLKEM768",
    TLS1_3_VERSION,
    "X25519MLKEM768",
    TLS1_3_VERSION,
    0,
    false,
  },

  // If the client supports hybrid TLS 1.3, but the server
  // only supports TLS 1.2, then TLS 1.2 EC should be negotiated.
  {
    "SecP256r1MLKEM768:prime256v1",
    TLS1_3_VERSION,
    "prime256v1:x25519",
    TLS1_2_VERSION,
    SSL_GROUP_SECP256R1,
    false,
  },

  // Same as above, but server also has SecP256r1MLKEM768 in it's
  // supported list, but can't use it since TLS 1.3 is the minimum version that
  // supports PQ.
  {
    "SecP256r1MLKEM768:prime256v1",
    TLS1_3_VERSION,
    "SecP256r1MLKEM768:prime256v1:x25519",
    TLS1_2_VERSION,
    SSL_GROUP_SECP256R1,
    false,
  },

  // If the client configures the curve list to include a hybrid
  // curve, then initiates a 1.2 handshake, it will not advertise
  // hybrid groups because hybrid is not supported for 1.2. So
  // a 1.2 EC handshake will be negotiated (even if the server
  // supports 1.3 with corresponding hybrid group).
  {
    "SecP256r1MLKEM768:x25519",
    TLS1_2_VERSION,
    "SecP256r1MLKEM768:x25519",
    TLS1_3_VERSION,
    SSL_GROUP_X25519,
    false,
  },
  {
    "SecP256r1MLKEM768:prime256v1",
    TLS1_2_VERSION,
    "prime256v1:x25519",
    TLS1_2_VERSION,
    SSL_GROUP_SECP256R1,
    false,
  },
};

const HybridGroup* GetHybridGroup(uint16_t group_id){
    for (const HybridGroup &g : HybridGroups()) {
      if (group_id == g.group_id) {
        return &g;
      }
    }

    return NULL;
}

static STACK_OF(SSL_CIPHER) *tls13_ciphers(const SSL_CTX *ctx) {
  return ctx->tls13_cipher_list->ciphers.get();
}

static std::string CipherListToString(SSL_CTX *ctx, bool tlsv13_ciphers) {
  bool in_group = false;
  std::string ret;
  const STACK_OF(SSL_CIPHER) *ciphers =
      tlsv13_ciphers ? tls13_ciphers(ctx) : SSL_CTX_get_ciphers(ctx);
  for (size_t i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
    const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
    if (!in_group && SSL_CTX_cipher_in_group(ctx, i)) {
      ret += "\t[\n";
      in_group = true;
    }
    ret += "\t";
    if (in_group) {
      ret += "  ";
    }
    ret += SSL_CIPHER_get_name(cipher);
    ret += "\n";
    if (in_group && !SSL_CTX_cipher_in_group(ctx, i)) {
      ret += "\t]\n";
      in_group = false;
    }
  }
  return ret;
}

static bool CipherListsEqual(SSL_CTX *ctx,
                             const std::vector<ExpectedCipher> &expected,
                             bool tlsv13_ciphers) {
  STACK_OF(SSL_CIPHER) *ciphers =
      tlsv13_ciphers ? tls13_ciphers(ctx) : SSL_CTX_get_ciphers(ctx);
  if (sk_SSL_CIPHER_num(ciphers) != expected.size()) {
    return false;
  }

  for (size_t i = 0; i < expected.size(); i++) {
    const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
    if (expected[i].id != SSL_CIPHER_get_id(cipher) ||
        expected[i].in_group_flag !=
            !!SSL_CTX_cipher_in_group(ctx, i)) {
      return false;
    }
  }

  return true;
}

// Functions used by SSL encode/decode tests.
static void EncodeAndDecodeSSL(SSL *in, SSL_CTX *ctx,
                               bssl::UniquePtr<SSL> *out) {
  // Encoding SSL to bytes.
  size_t encoded_len;
  bssl::UniquePtr<uint8_t> encoded;
  uint8_t *encoded_raw;
  ASSERT_TRUE(SSL_to_bytes(in, &encoded_raw, &encoded_len));
  ASSERT_TRUE(encoded_len) << "SSL_to_bytes failed. Error code: "
                           << ERR_reason_error_string(ERR_get_error());
  encoded.reset(encoded_raw);
  // Decoding SSL from the bytes.
  const uint8_t *ptr2 = encoded.get();
  SSL *server2_ = SSL_from_bytes(ptr2, encoded_len, ctx);
  ASSERT_TRUE(server2_) << "SSL_from_bytes failed. Error code: "
                        << ERR_reason_error_string(ERR_get_error());
  out->reset(server2_);
}

static void TransferBIOs(bssl::UniquePtr<SSL> *from, SSL *to) {
  // Fetch the bio.
  BIO *rbio = SSL_get_rbio(from->get());
  ASSERT_TRUE(rbio) << "rbio is not set"
                    << ERR_reason_error_string(ERR_get_error());
  BIO *wbio = SSL_get_wbio(from->get());
  ASSERT_TRUE(wbio) << "wbio is not set"
                    << ERR_reason_error_string(ERR_get_error());
  // Move the bio.
  // Increase ref count of |rbio|.
  // |SSL_set_bio(to, rbio, wbio)| only increments the references of |rbio| by 1
  // when |rbio == wbio|. But |SSL_free| decreases the reference of |rbio| and
  // |wbio|.
  if (rbio == wbio) {
    BIO_up_ref(rbio);
  }
  SSL_set_bio(to, rbio, wbio);
  // TODO: test half read and write hold by SSL.
  // TODO: add a test to check error code?
  // e.g. ASSERT_EQ(SSL_get_error(server1_, 0), SSL_ERROR_ZERO_RETURN);
  SSL_free(from->release());
}

// TransferSSL performs SSL transfer by
// 1. Encode the SSL of |in| into bytes.
// 2. Decode the bytes into a new SSL.
// 3. Free the SSL of |in|.
// 4. If |out| is not nullptr, |out| will hold the decoded SSL.
//    Else, |in| will get reset to hold the decoded SSL.
static void TransferSSL(bssl::UniquePtr<SSL> *in, SSL_CTX *in_ctx,
                        bssl::UniquePtr<SSL> *out) {
  bssl::UniquePtr<SSL> decoded_ssl;
  EncodeAndDecodeSSL(in->get(), in_ctx, &decoded_ssl);
  if (!decoded_ssl) {
    return;
  }
  // Transfer the bio.
  TransferBIOs(in, decoded_ssl.get());
  if (out == nullptr) {
    in->reset(decoded_ssl.release());
  } else {
    out->reset(decoded_ssl.release());
  }
}

TEST(GrowableArrayTest, Resize) {
  GrowableArray<size_t> array;
  ASSERT_TRUE(array.empty());
  EXPECT_EQ(array.size(), 0u);

  ASSERT_TRUE(array.Push(42));
  ASSERT_TRUE(!array.empty());
  EXPECT_EQ(array.size(), 1u);

  // Force a resize operation to occur
  for (size_t i = 0; i < 16; i++) {
    ASSERT_TRUE(array.Push(i + 1));
  }

  EXPECT_EQ(array.size(), 17u);

  // Verify that expected values are still contained in array
  for (size_t i = 0; i < array.size(); i++) {
    EXPECT_EQ(array[i], i == 0 ? 42 : i);
  }
}

TEST(GrowableArrayTest, MoveConstructor) {
  GrowableArray<size_t> array;
  for (size_t i = 0; i < 100; i++) {
    ASSERT_TRUE(array.Push(i));
  }

  GrowableArray<size_t> array_moved(std::move(array));
  for (size_t i = 0; i < 100; i++) {
    EXPECT_EQ(array_moved[i], i);
  }
}

TEST(GrowableArrayTest, GrowableArrayContainingGrowableArrays) {
  // Representative example of a struct that contains a GrowableArray.
  struct TagAndArray {
    size_t tag;
    GrowableArray<size_t> array;
  };

  GrowableArray<TagAndArray> array;
  for (size_t i = 0; i < 100; i++) {
    TagAndArray elem;
    elem.tag = i;
    for (size_t j = 0; j < i; j++) {
      ASSERT_TRUE(elem.array.Push(j));
    }
    ASSERT_TRUE(array.Push(std::move(elem)));
  }
  EXPECT_EQ(array.size(), static_cast<size_t>(100));

  GrowableArray<TagAndArray> array_moved(std::move(array));
  EXPECT_EQ(array_moved.size(), static_cast<size_t>(100));
  size_t count = 0;
  for (const TagAndArray &elem : array_moved) {
    // Test the square bracket operator returns the same value as iteration.
    EXPECT_EQ(&elem, &array_moved[count]);

    EXPECT_EQ(elem.tag, count);
    EXPECT_EQ(elem.array.size(), count);
    for (size_t j = 0; j < count; j++) {
      EXPECT_EQ(elem.array[j], j);
    }
    count++;
  }
}

TEST(SSLTest, CipherRules) {
  for (const CipherTest &t : kCipherTests) {
    SCOPED_TRACE(t.rule);
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(ctx);

    // We configure default TLS 1.3 ciphersuites in |SSL_CTX| which pollute
    // |ctx->cipher_list|. Set it to an empty list so we can test TLS 1.2
    // configurations.
    ASSERT_TRUE(SSL_CTX_set_ciphersuites(ctx.get(), ""));

    // Test lax mode.
    ASSERT_TRUE(SSL_CTX_set_cipher_list(ctx.get(), t.rule));
    EXPECT_TRUE(
        CipherListsEqual(ctx.get(), t.expected, false /* not TLSv1.3 only */))
        << "Cipher rule evaluated to:\n"
        << CipherListToString(ctx.get(), false /* not TLSv1.3 only */);

    // Test strict mode.
    if (t.strict_fail) {
      EXPECT_FALSE(SSL_CTX_set_strict_cipher_list(ctx.get(), t.rule));
    } else {
      ASSERT_TRUE(SSL_CTX_set_strict_cipher_list(ctx.get(), t.rule));
      EXPECT_TRUE(
          CipherListsEqual(ctx.get(), t.expected, false /* not TLSv1.3 only */))
          << "Cipher rule evaluated to:\n"
          << CipherListToString(ctx.get(), false /* not TLSv1.3 only */);
    }
  }

  for (const char *rule : kBadRules) {
    SCOPED_TRACE(rule);
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(ctx);

    EXPECT_FALSE(SSL_CTX_set_cipher_list(ctx.get(), rule));
    ERR_clear_error();
  }

  // kTLSv13RuleOnly are valid test cases for |SSL_CTX_set_ciphersuites|,
  // which configures only TLSv1.3 ciphers.
  // |SSL_CTX_set_cipher_list| only supports TLSv1.2 and below ciphers
  // configuration. Accordingly, kTLSv13RuleOnly result in
  // |SSL_R_NO_CIPHER_MATCH|.
  for (const CipherTest &t : kTLSv13RuleOnly) {
    SCOPED_TRACE(t.rule);
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(ctx);

    // We configure default TLS 1.3 ciphersuites in |SSL_CTX| which pollute
    // |ctx->cipher_list|. Set it to an empty list so we can test TLS 1.2
    // configurations.
    ASSERT_TRUE(SSL_CTX_set_ciphersuites(ctx.get(), ""));

    EXPECT_FALSE(SSL_CTX_set_cipher_list(ctx.get(), t.rule));
    ASSERT_EQ(ERR_GET_REASON(ERR_get_error()), SSL_R_NO_CIPHER_MATCH);
    ERR_clear_error();
  }

  for (const char *rule : kMustNotIncludeNull) {
    SCOPED_TRACE(rule);
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(ctx);

    ASSERT_TRUE(SSL_CTX_set_strict_cipher_list(ctx.get(), rule));
    for (const SSL_CIPHER *cipher : SSL_CTX_get_ciphers(ctx.get())) {
      EXPECT_NE(NID_undef, SSL_CIPHER_get_cipher_nid(cipher));
    }
  }

  for (const char *rule : kMustNotInclude3DES) {
    SCOPED_TRACE(rule);
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(ctx);

    ASSERT_TRUE(SSL_CTX_set_strict_cipher_list(ctx.get(), rule));
    for (const SSL_CIPHER *cipher : SSL_CTX_get_ciphers(ctx.get())) {
      EXPECT_NE(NID_des_ede3_cbc, SSL_CIPHER_get_cipher_nid(cipher));
    }
  }
}

static std::vector<CipherTest> combine_tests(const CipherTest *c1,
                                             size_t size_1,
                                             const CipherTest *c2,
                                             size_t size_2) {
  std::vector<CipherTest> ret(size_1 + size_2);
  size_t j = 0;
  for (size_t i = 0; i < size_1; i++) {
    ret[j++] = c1[i];
  }
  for (size_t i = 0; i < size_2; i++) {
    ret[j++] = c2[i];
  }
  return ret;
}

TEST(SSLTest, TLSv13CipherRules) {
  std::vector<CipherTest> cipherRules =
      combine_tests(kTLSv13RuleOnly, OPENSSL_ARRAY_SIZE(kTLSv13RuleOnly),
                    kTLSv13CipherTests, OPENSSL_ARRAY_SIZE(kTLSv13CipherTests));
  for (const CipherTest &t : cipherRules) {
    SCOPED_TRACE(t.rule);
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(ctx);
    bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
    ASSERT_TRUE(ssl);

    // Test lax mode.
    ASSERT_TRUE(SSL_CTX_set_ciphersuites(ctx.get(), t.rule));
    ASSERT_TRUE(SSL_set_ciphersuites(ssl.get(), t.rule));
    EXPECT_TRUE(
        CipherListsEqual(ctx.get(), t.expected, true /* TLSv1.3 only */))
        << "Cipher rule evaluated to:\n"
        << CipherListToString(ctx.get(), true /* TLSv1.3 only */);

    // TODO: add |SSL_CTX_set_strict_ciphersuites| and test strict mode.
  }

  for (const char *rule : kBadRules) {
    SCOPED_TRACE(rule);
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(ctx);
    bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
    ASSERT_TRUE(ssl);

    EXPECT_FALSE(SSL_CTX_set_ciphersuites(ctx.get(), rule));
    EXPECT_FALSE(SSL_set_ciphersuites(ssl.get(), rule));
    ERR_clear_error();
  }

  for (const char *rule : kTLSv13MustNotIncludeNull) {
    SCOPED_TRACE(rule);
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(ctx);
    bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
    ASSERT_TRUE(ssl);

    ASSERT_TRUE(SSL_CTX_set_ciphersuites(ctx.get(), rule));
    ASSERT_TRUE(SSL_set_ciphersuites(ssl.get(), rule));
    // Currenly, only three TLSv1.3 ciphers are supported.
    EXPECT_EQ(3u, sk_SSL_CIPHER_num(tls13_ciphers(ctx.get())));
    for (const SSL_CIPHER *cipher : tls13_ciphers(ctx.get())) {
      EXPECT_NE(NID_undef, SSL_CIPHER_get_cipher_nid(cipher));
    }
  }

  // kCipherTests are valid test cases for |SSL_CTX_set_cipher_list|,
  // which configures only TLSv1.2 and below ciphers.
  // |SSL_CTX_set_ciphersuites| only supports TLSv1.3 ciphers configuration.
  // Accordingly, kCipherTests result in |SSL_R_NO_CIPHER_MATCH|.
  // If kCipherTests starts to include rules that can match TLSv1.3 ciphers,
  // kCipherTests should get splitted.
  for (const CipherTest &t : kCipherTests) {
    SCOPED_TRACE(t.rule);
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(ctx);
    bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
    ASSERT_TRUE(ssl);

    EXPECT_FALSE(SSL_CTX_set_ciphersuites(ctx.get(), t.rule));
    EXPECT_FALSE(SSL_set_ciphersuites(ssl.get(), t.rule));
    ASSERT_EQ(ERR_GET_REASON(ERR_get_error()), SSL_R_NO_CIPHER_MATCH);
    ERR_clear_error();
  }
}

TEST(SSLTest, CurveRules) {
  for (const CurveTest &t : kCurveTests) {
    SCOPED_TRACE(t.rule);
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(ctx);

    ASSERT_TRUE(SSL_CTX_set1_groups_list(ctx.get(), t.rule));
    ASSERT_EQ(t.expected.size(), ctx->supported_group_list.size());
    for (size_t i = 0; i < t.expected.size(); i++) {
      EXPECT_EQ(t.expected[i], ctx->supported_group_list[i]);
    }
  }

  for (const char *rule : kBadCurvesLists) {
    SCOPED_TRACE(rule);
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(ctx);

    EXPECT_FALSE(SSL_CTX_set1_groups_list(ctx.get(), rule));
    ERR_clear_error();
  }
}

// kOpenSSLSession is a serialized SSL_SESSION.
static const char kOpenSSLSession[] =
    "MIIFqgIBAQICAwMEAsAvBCAG5Q1ndq4Yfmbeo1zwLkNRKmCXGdNgWvGT3cskV0yQ"
    "kAQwJlrlzkAWBOWiLj/jJ76D7l+UXoizP2KI2C7I2FccqMmIfFmmkUy32nIJ0mZH"
    "IWoJoQYCBFRDO46iBAICASyjggR6MIIEdjCCA16gAwIBAgIIK9dUvsPWSlUwDQYJ"
    "KoZIhvcNAQEFBQAwSTELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMx"
    "JTAjBgNVBAMTHEdvb2dsZSBJbnRlcm5ldCBBdXRob3JpdHkgRzIwHhcNMTQxMDA4"
    "MTIwNzU3WhcNMTUwMTA2MDAwMDAwWjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwK"
    "Q2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzETMBEGA1UECgwKR29v"
    "Z2xlIEluYzEXMBUGA1UEAwwOd3d3Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEB"
    "AQUAA4IBDwAwggEKAoIBAQCcKeLrplAC+Lofy8t/wDwtB6eu72CVp0cJ4V3lknN6"
    "huH9ct6FFk70oRIh/VBNBBz900jYy+7111Jm1b8iqOTQ9aT5C7SEhNcQFJvqzH3e"
    "MPkb6ZSWGm1yGF7MCQTGQXF20Sk/O16FSjAynU/b3oJmOctcycWYkY0ytS/k3LBu"
    "Id45PJaoMqjB0WypqvNeJHC3q5JjCB4RP7Nfx5jjHSrCMhw8lUMW4EaDxjaR9KDh"
    "PLgjsk+LDIySRSRDaCQGhEOWLJZVLzLo4N6/UlctCHEllpBUSvEOyFga52qroGjg"
    "rf3WOQ925MFwzd6AK+Ich0gDRg8sQfdLH5OuP1cfLfU1AgMBAAGjggFBMIIBPTAd"
    "BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdv"
    "b2dsZS5jb20waAYIKwYBBQUHAQEEXDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtp"
    "Lmdvb2dsZS5jb20vR0lBRzIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50"
    "czEuZ29vZ2xlLmNvbS9vY3NwMB0GA1UdDgQWBBQ7a+CcxsZByOpc+xpYFcIbnUMZ"
    "hTAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEv"
    "MBcGA1UdIAQQMA4wDAYKKwYBBAHWeQIFATAwBgNVHR8EKTAnMCWgI6Ahhh9odHRw"
    "Oi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQCa"
    "OXCBdoqUy5bxyq+Wrh1zsyyCFim1PH5VU2+yvDSWrgDY8ibRGJmfff3r4Lud5kal"
    "dKs9k8YlKD3ITG7P0YT/Rk8hLgfEuLcq5cc0xqmE42xJ+Eo2uzq9rYorc5emMCxf"
    "5L0TJOXZqHQpOEcuptZQ4OjdYMfSxk5UzueUhA3ogZKRcRkdB3WeWRp+nYRhx4St"
    "o2rt2A0MKmY9165GHUqMK9YaaXHDXqBu7Sefr1uSoAP9gyIJKeihMivsGqJ1TD6Z"
    "cc6LMe+dN2P8cZEQHtD1y296ul4Mivqk3jatUVL8/hCwgch9A8O4PGZq9WqBfEWm"
    "IyHh1dPtbg1lOXdYCWtjpAIEAKUDAgEUqQUCAwGJwKqBpwSBpBwUQvoeOk0Kg36S"
    "YTcLEkXqKwOBfF9vE4KX0NxeLwjcDTpsuh3qXEaZ992r1N38VDcyS6P7I6HBYN9B"
    "sNHM362zZnY27GpTw+Kwd751CLoXFPoaMOe57dbBpXoro6Pd3BTbf/Tzr88K06yE"
    "OTDKPNj3+inbMaVigtK4PLyPq+Topyzvx9USFgRvyuoxn0Hgb+R0A3j6SLRuyOdA"
    "i4gv7Y5oliyntgMBAQA=";

// kCustomSession is a custom serialized SSL_SESSION generated by
// filling in missing fields from |kOpenSSLSession|. This includes
// providing |peer_sha256|, so |peer| is not serialized.
static const char kCustomSession[] =
    "MIIBZAIBAQICAwMEAsAvBCAG5Q1ndq4Yfmbeo1zwLkNRKmCXGdNgWvGT3cskV0yQ"
    "kAQwJlrlzkAWBOWiLj/jJ76D7l+UXoizP2KI2C7I2FccqMmIfFmmkUy32nIJ0mZH"
    "IWoJoQYCBFRDO46iBAICASykAwQBAqUDAgEUqAcEBXdvcmxkqQUCAwGJwKqBpwSB"
    "pBwUQvoeOk0Kg36SYTcLEkXqKwOBfF9vE4KX0NxeLwjcDTpsuh3qXEaZ992r1N38"
    "VDcyS6P7I6HBYN9BsNHM362zZnY27GpTw+Kwd751CLoXFPoaMOe57dbBpXoro6Pd"
    "3BTbf/Tzr88K06yEOTDKPNj3+inbMaVigtK4PLyPq+Topyzvx9USFgRvyuoxn0Hg"
    "b+R0A3j6SLRuyOdAi4gv7Y5oliynrSIEIAYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG"
    "BgYGBgYGBgYGrgMEAQevAwQBBLADBAEF";

// kBoringSSLSession is a serialized SSL_SESSION generated from bssl client.
static const char kBoringSSLSession[] =
    "MIIRwQIBAQICAwMEAsAvBCDdoGxGK26mR+8lM0uq6+k9xYuxPnwAjpcF9n0Yli9R"
    "kQQwbyshfWhdi5XQ1++7n2L1qqrcVlmHBPpr6yknT/u4pUrpQB5FZ7vqvNn8MdHf"
    "9rWgoQYCBFXgs7uiBAICHCCjggR6MIIEdjCCA16gAwIBAgIIf+yfD7Y6UicwDQYJ"
    "KoZIhvcNAQELBQAwSTELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMx"
    "JTAjBgNVBAMTHEdvb2dsZSBJbnRlcm5ldCBBdXRob3JpdHkgRzIwHhcNMTUwODEy"
    "MTQ1MzE1WhcNMTUxMTEwMDAwMDAwWjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwK"
    "Q2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzETMBEGA1UECgwKR29v"
    "Z2xlIEluYzEXMBUGA1UEAwwOd3d3Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEB"
    "AQUAA4IBDwAwggEKAoIBAQC0MeG5YGQ0t+IeJeoneP/PrhEaieibeKYkbKVLNZpo"
    "PLuBinvhkXZo3DC133NpCBpy6ZktBwamqyixAyuk/NU6OjgXqwwxfQ7di1AInLIU"
    "792c7hFyNXSUCG7At8Ifi3YwBX9Ba6u/1d6rWTGZJrdCq3QU11RkKYyTq2KT5mce"
    "Tv9iGKqSkSTlp8puy/9SZ/3DbU3U+BuqCFqeSlz7zjwFmk35acdCilpJlVDDN5C/"
    "RCh8/UKc8PaL+cxlt531qoTENvYrflBno14YEZlCBZsPiFeUSILpKEj3Ccwhy0eL"
    "EucWQ72YZU8mUzXBoXGn0zA0crFl5ci/2sTBBGZsylNBAgMBAAGjggFBMIIBPTAd"
    "BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdv"
    "b2dsZS5jb20waAYIKwYBBQUHAQEEXDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtp"
    "Lmdvb2dsZS5jb20vR0lBRzIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50"
    "czEuZ29vZ2xlLmNvbS9vY3NwMB0GA1UdDgQWBBS/bzHxcE73Q4j3slC4BLbMtLjG"
    "GjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEv"
    "MBcGA1UdIAQQMA4wDAYKKwYBBAHWeQIFATAwBgNVHR8EKTAnMCWgI6Ahhh9odHRw"
    "Oi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQAb"
    "qdWPZEHk0X7iKPCTHL6S3w6q1eR67goxZGFSM1lk1hjwyu7XcLJuvALVV9uY3ovE"
    "kQZSHwT+pyOPWQhsSjO+1GyjvCvK/CAwiUmBX+bQRGaqHsRcio7xSbdVcajQ3bXd"
    "X+s0WdbOpn6MStKAiBVloPlSxEI8pxY6x/BBCnTIk/+DMB17uZlOjG3vbAnkDkP+"
    "n0OTucD9sHV7EVj9XUxi51nOfNBCN/s7lpUjDS/NJ4k3iwOtbCPswiot8vLO779a"
    "f07vR03r349Iz/KTzk95rlFtX0IU+KYNxFNsanIXZ+C9FYGRXkwhHcvFb4qMUB1y"
    "TTlM80jBMOwyjZXmjRAhpAIEAKUDAgEUqQUCAwGJwKqBpwSBpOgebbmn9NRUtMWH"
    "+eJpqA5JLMFSMCChOsvKey3toBaCNGU7HfAEiiXNuuAdCBoK262BjQc2YYfqFzqH"
    "zuppopXCvhohx7j/tnCNZIMgLYt/O9SXK2RYI5z8FhCCHvB4CbD5G0LGl5EFP27s"
    "Jb6S3aTTYPkQe8yZSlxevg6NDwmTogLO9F7UUkaYmVcMQhzssEE2ZRYNwSOU6KjE"
    "0Yj+8fAiBtbQriIEIN2L8ZlpaVrdN5KFNdvcmOxJu81P8q53X55xQyGTnGWwsgMC"
    "ARezggvvMIIEdjCCA16gAwIBAgIIf+yfD7Y6UicwDQYJKoZIhvcNAQELBQAwSTEL"
    "MAkGA1UEBhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2ds"
    "ZSBJbnRlcm5ldCBBdXRob3JpdHkgRzIwHhcNMTUwODEyMTQ1MzE1WhcNMTUxMTEw"
    "MDAwMDAwWjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQG"
    "A1UEBwwNTW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UE"
    "AwwOd3d3Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB"
    "AQC0MeG5YGQ0t+IeJeoneP/PrhEaieibeKYkbKVLNZpoPLuBinvhkXZo3DC133Np"
    "CBpy6ZktBwamqyixAyuk/NU6OjgXqwwxfQ7di1AInLIU792c7hFyNXSUCG7At8If"
    "i3YwBX9Ba6u/1d6rWTGZJrdCq3QU11RkKYyTq2KT5mceTv9iGKqSkSTlp8puy/9S"
    "Z/3DbU3U+BuqCFqeSlz7zjwFmk35acdCilpJlVDDN5C/RCh8/UKc8PaL+cxlt531"
    "qoTENvYrflBno14YEZlCBZsPiFeUSILpKEj3Ccwhy0eLEucWQ72YZU8mUzXBoXGn"
    "0zA0crFl5ci/2sTBBGZsylNBAgMBAAGjggFBMIIBPTAdBgNVHSUEFjAUBggrBgEF"
    "BQcDAQYIKwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20waAYIKwYB"
    "BQUHAQEEXDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lB"
    "RzIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9v"
    "Y3NwMB0GA1UdDgQWBBS/bzHxcE73Q4j3slC4BLbMtLjGGjAMBgNVHRMBAf8EAjAA"
    "MB8GA1UdIwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMBcGA1UdIAQQMA4wDAYK"
    "KwYBBAHWeQIFATAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGtpLmdvb2dsZS5j"
    "b20vR0lBRzIuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQAbqdWPZEHk0X7iKPCTHL6S"
    "3w6q1eR67goxZGFSM1lk1hjwyu7XcLJuvALVV9uY3ovEkQZSHwT+pyOPWQhsSjO+"
    "1GyjvCvK/CAwiUmBX+bQRGaqHsRcio7xSbdVcajQ3bXdX+s0WdbOpn6MStKAiBVl"
    "oPlSxEI8pxY6x/BBCnTIk/+DMB17uZlOjG3vbAnkDkP+n0OTucD9sHV7EVj9XUxi"
    "51nOfNBCN/s7lpUjDS/NJ4k3iwOtbCPswiot8vLO779af07vR03r349Iz/KTzk95"
    "rlFtX0IU+KYNxFNsanIXZ+C9FYGRXkwhHcvFb4qMUB1yTTlM80jBMOwyjZXmjRAh"
    "MIID8DCCAtigAwIBAgIDAjqDMA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNVBAYTAlVT"
    "MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i"
    "YWwgQ0EwHhcNMTMwNDA1MTUxNTU2WhcNMTYxMjMxMjM1OTU5WjBJMQswCQYDVQQG"
    "EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy"
    "bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB"
    "AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP"
    "VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv"
    "h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE"
    "ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ"
    "EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC"
    "DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB5zCB5DAfBgNVHSMEGDAWgBTAephojYn7"
    "qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wDgYD"
    "VR0PAQH/BAQDAgEGMC4GCCsGAQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDov"
    "L2cuc3ltY2QuY29tMBIGA1UdEwEB/wQIMAYBAf8CAQAwNQYDVR0fBC4wLDAqoCig"
    "JoYkaHR0cDovL2cuc3ltY2IuY29tL2NybHMvZ3RnbG9iYWwuY3JsMBcGA1UdIAQQ"
    "MA4wDAYKKwYBBAHWeQIFATANBgkqhkiG9w0BAQsFAAOCAQEAqvqpIM1qZ4PtXtR+"
    "3h3Ef+AlBgDFJPupyC1tft6dgmUsgWM0Zj7pUsIItMsv91+ZOmqcUHqFBYx90SpI"
    "hNMJbHzCzTWf84LuUt5oX+QAihcglvcpjZpNy6jehsgNb1aHA30DP9z6eX0hGfnI"
    "Oi9RdozHQZJxjyXON/hKTAAj78Q1EK7gI4BzfE00LshukNYQHpmEcxpw8u1VDu4X"
    "Bupn7jLrLN1nBz/2i8Jw3lsA5rsb0zYaImxssDVCbJAJPZPpZAkiDoUGn8JzIdPm"
    "X4DkjYUiOnMDsWCOrmji9D6X52ASCWg23jrW4kOVWzeBkoEfu43XrVJkFleW2V40"
    "fsg12DCCA30wggLmoAMCAQICAxK75jANBgkqhkiG9w0BAQUFADBOMQswCQYDVQQG"
    "EwJVUzEQMA4GA1UEChMHRXF1aWZheDEtMCsGA1UECxMkRXF1aWZheCBTZWN1cmUg"
    "Q2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTAyMDUyMTA0MDAwMFoXDTE4MDgyMTA0"
    "MDAwMFowQjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUdlb1RydXN0IEluYy4xGzAZ"
    "BgNVBAMTEkdlb1RydXN0IEdsb2JhbCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP"
    "ADCCAQoCggEBANrMGGMw/fQXIxpWflvfPGw45HG3eJHUvKHYTPioQ7YD6U0hBwiI"
    "2lgvZjkpvQV4i5046AW3an5xpObEYKaw74DkiSgPniXW7YPzraaRx5jJQhg1FJ2t"
    "mEaSLk/K8YdDwRaVVy1Q74ktgHpXrfLuX2vSAI25FPgUFTXZwEaje3LIkb/JVSvN"
    "0Jc+nCZkzN/Ogxlxyk7m1NV7qRnNVd7I7NJeOFPlXE+MLf5QIzb8ZubLjqQ5GQC3"
    "lQI5kQsO/jgu0R0FmvZNPm8PBx2vLB6PYDni+jZTEznUXiYr2z2oFL0y6xgDKFIE"
    "ceWrMz3hOLsHNoRinHnqFjD0X8Ar6HFr5PkCAwEAAaOB8DCB7TAfBgNVHSMEGDAW"
    "gBRI5mj5K9KylddH2CMgEE8zmJCf1DAdBgNVHQ4EFgQUwHqYaI2J+6sFZAwRfap9"
    "ZbjKzE4wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMw"
    "MTAvoC2gK4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9zZWN1cmVjYS5j"
    "cmwwTgYDVR0gBEcwRTBDBgRVHSAAMDswOQYIKwYBBQUHAgEWLWh0dHBzOi8vd3d3"
    "Lmdlb3RydXN0LmNvbS9yZXNvdXJjZXMvcmVwb3NpdG9yeTANBgkqhkiG9w0BAQUF"
    "AAOBgQB24RJuTksWEoYwBrKBCM/wCMfHcX5m7sLt1Dsf//DwyE7WQziwuTB9GNBV"
    "g6JqyzYRnOhIZqNtf7gT1Ef+i1pcc/yu2RsyGTirlzQUqpbS66McFAhJtrvlke+D"
    "NusdVm/K2rxzY5Dkf3s+Iss9B+1fOHSc4wNQTqGvmO5h8oQ/Eg==";

// kBadSessionExtraField is a custom serialized SSL_SESSION generated by
// replacing the final (optional) element of |kCustomSession| with tag
// number 99.
static const char kBadSessionExtraField[] =
    "MIIBdgIBAQICAwMEAsAvBCAG5Q1ndq4Yfmbeo1zwLkNRKmCXGdNgWvGT3cskV0yQ"
    "kAQwJlrlzkAWBOWiLj/jJ76D7l+UXoizP2KI2C7I2FccqMmIfFmmkUy32nIJ0mZH"
    "IWoJoQYCBFRDO46iBAICASykAwQBAqUDAgEUphAEDnd3dy5nb29nbGUuY29tqAcE"
    "BXdvcmxkqQUCAwGJwKqBpwSBpBwUQvoeOk0Kg36SYTcLEkXqKwOBfF9vE4KX0Nxe"
    "LwjcDTpsuh3qXEaZ992r1N38VDcyS6P7I6HBYN9BsNHM362zZnY27GpTw+Kwd751"
    "CLoXFPoaMOe57dbBpXoro6Pd3BTbf/Tzr88K06yEOTDKPNj3+inbMaVigtK4PLyP"
    "q+Topyzvx9USFgRvyuoxn0Hgb+R0A3j6SLRuyOdAi4gv7Y5oliynrSIEIAYGBgYG"
    "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGrgMEAQevAwQBBOMDBAEF";

// kBadSessionVersion is a custom serialized SSL_SESSION generated by replacing
// the version of |kCustomSession| with 2.
static const char kBadSessionVersion[] =
    "MIIBdgIBAgICAwMEAsAvBCAG5Q1ndq4Yfmbeo1zwLkNRKmCXGdNgWvGT3cskV0yQ"
    "kAQwJlrlzkAWBOWiLj/jJ76D7l+UXoizP2KI2C7I2FccqMmIfFmmkUy32nIJ0mZH"
    "IWoJoQYCBFRDO46iBAICASykAwQBAqUDAgEUphAEDnd3dy5nb29nbGUuY29tqAcE"
    "BXdvcmxkqQUCAwGJwKqBpwSBpBwUQvoeOk0Kg36SYTcLEkXqKwOBfF9vE4KX0Nxe"
    "LwjcDTpsuh3qXEaZ992r1N38VDcyS6P7I6HBYN9BsNHM362zZnY27GpTw+Kwd751"
    "CLoXFPoaMOe57dbBpXoro6Pd3BTbf/Tzr88K06yEOTDKPNj3+inbMaVigtK4PLyP"
    "q+Topyzvx9USFgRvyuoxn0Hgb+R0A3j6SLRuyOdAi4gv7Y5oliynrSIEIAYGBgYG"
    "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGrgMEAQevAwQBBLADBAEF";

// kBadSessionTrailingData is a custom serialized SSL_SESSION with trailing data
// appended.
static const char kBadSessionTrailingData[] =
    "MIIBdgIBAQICAwMEAsAvBCAG5Q1ndq4Yfmbeo1zwLkNRKmCXGdNgWvGT3cskV0yQ"
    "kAQwJlrlzkAWBOWiLj/jJ76D7l+UXoizP2KI2C7I2FccqMmIfFmmkUy32nIJ0mZH"
    "IWoJoQYCBFRDO46iBAICASykAwQBAqUDAgEUphAEDnd3dy5nb29nbGUuY29tqAcE"
    "BXdvcmxkqQUCAwGJwKqBpwSBpBwUQvoeOk0Kg36SYTcLEkXqKwOBfF9vE4KX0Nxe"
    "LwjcDTpsuh3qXEaZ992r1N38VDcyS6P7I6HBYN9BsNHM362zZnY27GpTw+Kwd751"
    "CLoXFPoaMOe57dbBpXoro6Pd3BTbf/Tzr88K06yEOTDKPNj3+inbMaVigtK4PLyP"
    "q+Topyzvx9USFgRvyuoxn0Hgb+R0A3j6SLRuyOdAi4gv7Y5oliynrSIEIAYGBgYG"
    "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGrgMEAQevAwQBBLADBAEFAAAA";

static bool DecodeBase64(std::vector<uint8_t> *out, const char *in) {
  size_t len;
  if (!EVP_DecodedLength(&len, strlen(in))) {
    fprintf(stderr, "EVP_DecodedLength failed\n");
    return false;
  }

  out->resize(len);
  if (!EVP_DecodeBase64(out->data(), &len, len, (const uint8_t *)in,
                        strlen(in))) {
    fprintf(stderr, "EVP_DecodeBase64 failed\n");
    return false;
  }
  out->resize(len);
  return true;
}

TEST(SSLTest, SessionEncoding) {
  for (const char *input_b64 : {
           kOpenSSLSession,
           kCustomSession,
           kBoringSSLSession,
       }) {
    SCOPED_TRACE(std::string(input_b64));
    // Decode the input.
    std::vector<uint8_t> input;
    ASSERT_TRUE(DecodeBase64(&input, input_b64));

    // Verify the SSL_SESSION decodes.
    bssl::UniquePtr<SSL_CTX> ssl_ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(ssl_ctx);
    bssl::UniquePtr<SSL_SESSION> session(
        SSL_SESSION_from_bytes(input.data(), input.size(), ssl_ctx.get()));
    ASSERT_TRUE(session) << "SSL_SESSION_from_bytes failed";

    // Verify the SSL_SESSION encoding round-trips.
    size_t encoded_len;
    bssl::UniquePtr<uint8_t> encoded;
    uint8_t *encoded_raw;
    ASSERT_TRUE(SSL_SESSION_to_bytes(session.get(), &encoded_raw, &encoded_len))
        << "SSL_SESSION_to_bytes failed";
    encoded.reset(encoded_raw);
    EXPECT_EQ(Bytes(encoded.get(), encoded_len), Bytes(input))
        << "SSL_SESSION_to_bytes did not round-trip";

    // Verify the SSL_SESSION also decodes with the legacy API.
    const uint8_t *cptr = input.data();
    session.reset(d2i_SSL_SESSION(NULL, &cptr, input.size()));
    ASSERT_TRUE(session) << "d2i_SSL_SESSION failed";
    EXPECT_EQ(cptr, input.data() + input.size());

    // Verify the SSL_SESSION encoding round-trips via the legacy API.
    int len = i2d_SSL_SESSION(session.get(), NULL);
    ASSERT_GT(len, 0) << "i2d_SSL_SESSION failed";
    ASSERT_EQ(static_cast<size_t>(len), input.size())
        << "i2d_SSL_SESSION(NULL) returned invalid length";

    encoded.reset((uint8_t *)OPENSSL_malloc(input.size()));
    ASSERT_TRUE(encoded);

    uint8_t *ptr = encoded.get();
    len = i2d_SSL_SESSION(session.get(), &ptr);
    ASSERT_GT(len, 0) << "i2d_SSL_SESSION failed";
    ASSERT_EQ(static_cast<size_t>(len), input.size())
        << "i2d_SSL_SESSION(NULL) returned invalid length";
    ASSERT_EQ(ptr, encoded.get() + input.size())
        << "i2d_SSL_SESSION did not advance ptr correctly";
    EXPECT_EQ(Bytes(encoded.get(), encoded_len), Bytes(input))
        << "SSL_SESSION_to_bytes did not round-trip";

    // Verify that |i2d_SSL_SESSION| works correctly when |pp| is non-NULL, but
    // |*pp| is NULL. A newly-allocated buffer containing the result should be
    // created. See |i2d_SAMPLE| for more details.
    uint8_t *ptr2 = nullptr;
    int len2 = i2d_SSL_SESSION(session.get(), &ptr2);
    ASSERT_TRUE(ptr2);
    ASSERT_GT(len2, 0);
    bssl::UniquePtr<uint8_t> encoded2(ptr2);
    EXPECT_EQ(Bytes(encoded2.get(), len2), Bytes(input))
        << "SSL_SESSION_to_bytes did not round-trip";
  }

  for (const char *input_b64 : {
           kBadSessionExtraField,
           kBadSessionVersion,
           kBadSessionTrailingData,
       }) {
    SCOPED_TRACE(std::string(input_b64));
    std::vector<uint8_t> input;
    ASSERT_TRUE(DecodeBase64(&input, input_b64));

    // Verify that the SSL_SESSION fails to decode.
    bssl::UniquePtr<SSL_CTX> ssl_ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(ssl_ctx);
    bssl::UniquePtr<SSL_SESSION> session(
        SSL_SESSION_from_bytes(input.data(), input.size(), ssl_ctx.get()));
    EXPECT_FALSE(session) << "SSL_SESSION_from_bytes unexpectedly succeeded";
    ERR_clear_error();
  }
}

static void ExpectDefaultVersion(uint16_t min_version, uint16_t max_version,
                                 const SSL_METHOD *(*method)(void)) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(method()));
  ASSERT_TRUE(ctx);
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);
  EXPECT_EQ(0, SSL_CTX_get_min_proto_version(ctx.get()));
  EXPECT_EQ(0, SSL_CTX_get_max_proto_version(ctx.get()));
  EXPECT_EQ(0, SSL_get_min_proto_version(ssl.get()));
  EXPECT_EQ(0, SSL_get_max_proto_version(ssl.get()));

  EXPECT_TRUE(SSL_CTX_set_min_proto_version(ctx.get(), min_version));
  EXPECT_TRUE(SSL_CTX_set_max_proto_version(ctx.get(), max_version));
  EXPECT_EQ(min_version, SSL_CTX_get_min_proto_version(ctx.get()));
  EXPECT_EQ(max_version, SSL_CTX_get_max_proto_version(ctx.get()));
  EXPECT_TRUE(SSL_set_min_proto_version(ssl.get(), min_version));
  EXPECT_TRUE(SSL_set_max_proto_version(ssl.get(), max_version));
  EXPECT_EQ(min_version, SSL_get_min_proto_version(ssl.get()));
  EXPECT_EQ(max_version, SSL_get_max_proto_version(ssl.get()));
}

TEST(SSLTest, DefaultVersion) {
  ExpectDefaultVersion(TLS1_VERSION, TLS1_3_VERSION, &TLS_method);
  ExpectDefaultVersion(TLS1_VERSION, TLS1_VERSION, &TLSv1_method);
  ExpectDefaultVersion(TLS1_1_VERSION, TLS1_1_VERSION, &TLSv1_1_method);
  ExpectDefaultVersion(TLS1_2_VERSION, TLS1_2_VERSION, &TLSv1_2_method);
  ExpectDefaultVersion(DTLS1_VERSION, DTLS1_2_VERSION, &DTLS_method);
  ExpectDefaultVersion(DTLS1_VERSION, DTLS1_VERSION, &DTLSv1_method);
  ExpectDefaultVersion(DTLS1_2_VERSION, DTLS1_2_VERSION, &DTLSv1_2_method);
}

TEST(SSLTest, CipherProperties) {
  static const struct {
    int id;
    const char *standard_name;
    int cipher_nid;
    int digest_nid;
    int kx_nid;
    int auth_nid;
    int prf_nid;
  } kTests[] = {
      {
          SSL3_CK_RSA_DES_192_CBC3_SHA,
          "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
          NID_des_ede3_cbc,
          NID_sha1,
          NID_kx_rsa,
          NID_auth_rsa,
          NID_md5_sha1,
      },
      {
          TLS1_CK_RSA_WITH_AES_128_SHA,
          "TLS_RSA_WITH_AES_128_CBC_SHA",
          NID_aes_128_cbc,
          NID_sha1,
          NID_kx_rsa,
          NID_auth_rsa,
          NID_md5_sha1,
      },
      {
          TLS1_CK_RSA_WITH_AES_128_SHA256,
          "TLS_RSA_WITH_AES_128_CBC_SHA256",
          NID_aes_128_cbc,
          NID_sha256,
          NID_kx_rsa,
          NID_auth_rsa,
          NID_sha256,
      },
      {
          TLS1_CK_PSK_WITH_AES_256_CBC_SHA,
          "TLS_PSK_WITH_AES_256_CBC_SHA",
          NID_aes_256_cbc,
          NID_sha1,
          NID_kx_psk,
          NID_auth_psk,
          NID_md5_sha1,
      },
      {
          TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA,
          "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
          NID_aes_128_cbc,
          NID_sha1,
          NID_kx_ecdhe,
          NID_auth_rsa,
          NID_md5_sha1,
      },
      {
          TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256,
          "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
          NID_aes_128_cbc,
          NID_sha256,
          NID_kx_ecdhe,
          NID_auth_rsa,
          NID_sha256,
      },
      {
          TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA,
          "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
          NID_aes_256_cbc,
          NID_sha1,
          NID_kx_ecdhe,
          NID_auth_rsa,
          NID_md5_sha1,
      },
      {
          TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
          "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
          NID_aes_128_gcm,
          NID_undef,
          NID_kx_ecdhe,
          NID_auth_rsa,
          NID_sha256,
      },
      {
          TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
          "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
          NID_aes_128_gcm,
          NID_undef,
          NID_kx_ecdhe,
          NID_auth_ecdsa,
          NID_sha256,
      },
      {
          TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
          "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
          NID_aes_256_gcm,
          NID_undef,
          NID_kx_ecdhe,
          NID_auth_ecdsa,
          NID_sha384,
      },
      {
          TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA,
          "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
          NID_aes_128_cbc,
          NID_sha1,
          NID_kx_ecdhe,
          NID_auth_psk,
          NID_md5_sha1,
      },
      {
          TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
          "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
          NID_chacha20_poly1305,
          NID_undef,
          NID_kx_ecdhe,
          NID_auth_rsa,
          NID_sha256,
      },
      {
          TLS1_3_CK_AES_256_GCM_SHA384,
          "TLS_AES_256_GCM_SHA384",
          NID_aes_256_gcm,
          NID_undef,
          NID_kx_any,
          NID_auth_any,
          NID_sha384,
      },
      {
          TLS1_3_CK_AES_128_GCM_SHA256,
          "TLS_AES_128_GCM_SHA256",
          NID_aes_128_gcm,
          NID_undef,
          NID_kx_any,
          NID_auth_any,
          NID_sha256,
      },
      {
          TLS1_3_CK_CHACHA20_POLY1305_SHA256,
          "TLS_CHACHA20_POLY1305_SHA256",
          NID_chacha20_poly1305,
          NID_undef,
          NID_kx_any,
          NID_auth_any,
          NID_sha256,
      },
  };

  for (const auto &t : kTests) {
    SCOPED_TRACE(t.standard_name);

    const SSL_CIPHER *cipher = SSL_get_cipher_by_value(t.id & 0xffff);
    ASSERT_TRUE(cipher);
    EXPECT_STREQ(t.standard_name, SSL_CIPHER_standard_name(cipher));

    EXPECT_EQ(t.cipher_nid, SSL_CIPHER_get_cipher_nid(cipher));
    EXPECT_EQ(t.digest_nid, SSL_CIPHER_get_digest_nid(cipher));
    EXPECT_EQ(t.kx_nid, SSL_CIPHER_get_kx_nid(cipher));
    EXPECT_EQ(t.auth_nid, SSL_CIPHER_get_auth_nid(cipher));
    const EVP_MD *md = SSL_CIPHER_get_handshake_digest(cipher);
    ASSERT_TRUE(md);
    EXPECT_EQ(t.prf_nid, EVP_MD_nid(md));
    EXPECT_EQ(t.prf_nid, SSL_CIPHER_get_prf_nid(cipher));
  }
}

// CreateSessionWithTicket returns a sample |SSL_SESSION| with the specified
// version and ticket length or nullptr on failure.
static bssl::UniquePtr<SSL_SESSION> CreateSessionWithTicket(uint16_t version,
                                                            size_t ticket_len) {
  std::vector<uint8_t> der;
  if (!DecodeBase64(&der, kOpenSSLSession)) {
    return nullptr;
  }

  bssl::UniquePtr<SSL_CTX> ssl_ctx(SSL_CTX_new(TLS_method()));
  if (!ssl_ctx) {
    return nullptr;
  }
  // Use a garbage ticket.
  std::vector<uint8_t> ticket(ticket_len, 'a');
  bssl::UniquePtr<SSL_SESSION> session(
      SSL_SESSION_from_bytes(der.data(), der.size(), ssl_ctx.get()));
  if (!session || !SSL_SESSION_set_protocol_version(session.get(), version) ||
      !SSL_SESSION_set_ticket(session.get(), ticket.data(), ticket.size())) {
    return nullptr;
  }
  // Fix up the timeout.
#if defined(BORINGSSL_UNSAFE_DETERMINISTIC_MODE)
  SSL_SESSION_set_time(session.get(), 1234);
#else
  SSL_SESSION_set_time(session.get(), time(nullptr));
#endif
  return session;
}

static bool GetClientHello(SSL *ssl, std::vector<uint8_t> *out) {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!bio) {
    return false;
  }
  // Do not configure a reading BIO, but record what's written to a memory BIO.
  BIO_up_ref(bio.get());
  SSL_set_bio(ssl, nullptr /* rbio */, bio.get());
  int ret = SSL_connect(ssl);
  if (ret > 0) {
    // SSL_connect should fail without a BIO to write to.
    return false;
  }
  ERR_clear_error();

  const uint8_t *client_hello;
  size_t client_hello_len;
  if (!BIO_mem_contents(bio.get(), &client_hello, &client_hello_len)) {
    return false;
  }

  // We did not get far enough to write a ClientHello.
  if (client_hello_len == 0) {
    return false;
  }

  *out = std::vector<uint8_t>(client_hello, client_hello + client_hello_len);
  return true;
}

// GetClientHelloLen creates a client SSL connection with the specified version
// and ticket length. It returns the length of the ClientHello, not including
// the record header, on success and zero on error.
static size_t GetClientHelloLen(uint16_t max_version, uint16_t session_version,
                                size_t ticket_len) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_SESSION> session =
      CreateSessionWithTicket(session_version, ticket_len);
  if (!ctx || !session) {
    return 0;
  }

  // Set a one-element cipher list so the baseline ClientHello is unpadded.
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  if (!ssl || !SSL_set_session(ssl.get(), session.get()) ||
      !SSL_set_strict_cipher_list(ssl.get(), "ECDHE-RSA-AES128-GCM-SHA256") ||
      !SSL_set_max_proto_version(ssl.get(), max_version)) {
    return 0;
  }

  std::vector<uint8_t> client_hello;
  if (!GetClientHello(ssl.get(), &client_hello) ||
      client_hello.size() <= SSL3_RT_HEADER_LENGTH) {
    return 0;
  }

  return client_hello.size() - SSL3_RT_HEADER_LENGTH;
}

TEST(SSLTest, Padding) {
  struct PaddingVersions {
    uint16_t max_version, session_version;
  };
  static const PaddingVersions kPaddingVersions[] = {
      // Test the padding extension at TLS 1.2.
      {TLS1_2_VERSION, TLS1_2_VERSION},
      // Test the padding extension at TLS 1.3 with a TLS 1.2 session, so there
      // will be no PSK binder after the padding extension.
      {TLS1_3_VERSION, TLS1_2_VERSION},
      // Test the padding extension at TLS 1.3 with a TLS 1.3 session, so there
      // will be a PSK binder after the padding extension.
      {TLS1_3_VERSION, TLS1_3_VERSION},

  };

  struct PaddingTest {
    size_t input_len, padded_len;
  };
  static const PaddingTest kPaddingTests[] = {
      // ClientHellos of length below 0x100 do not require padding.
      {0xfe, 0xfe},
      {0xff, 0xff},
      // ClientHellos of length 0x100 through 0x1fb are padded up to 0x200.
      {0x100, 0x200},
      {0x123, 0x200},
      {0x1fb, 0x200},
      // ClientHellos of length 0x1fc through 0x1ff get padded beyond 0x200. The
      // padding extension takes a minimum of four bytes plus one required
      // content
      // byte. (To work around yet more server bugs, we avoid empty final
      // extensions.)
      {0x1fc, 0x201},
      {0x1fd, 0x202},
      {0x1fe, 0x203},
      {0x1ff, 0x204},
      // Finally, larger ClientHellos need no padding.
      {0x200, 0x200},
      {0x201, 0x201},
  };

  for (const PaddingVersions &versions : kPaddingVersions) {
    SCOPED_TRACE(versions.max_version);
    SCOPED_TRACE(versions.session_version);

    // Sample a baseline length.
    size_t base_len =
        GetClientHelloLen(versions.max_version, versions.session_version, 1);
    ASSERT_NE(base_len, 0u) << "Baseline length could not be sampled";

    for (const PaddingTest &test : kPaddingTests) {
      SCOPED_TRACE(test.input_len);
      ASSERT_LE(base_len, test.input_len) << "Baseline ClientHello too long";

      size_t padded_len =
          GetClientHelloLen(versions.max_version, versions.session_version,
                            1 + test.input_len - base_len);
      EXPECT_EQ(padded_len, test.padded_len)
          << "ClientHello was not padded to expected length";
    }
  }
}

static bssl::UniquePtr<EVP_PKEY> KeyFromPEM(const char *pem) {
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem, strlen(pem)));
  if (!bio) {
    return nullptr;
  }
  return bssl::UniquePtr<EVP_PKEY>(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
}

static bssl::UniquePtr<X509> GetTestCertificate() {
  static const char kCertPEM[] =
      "-----BEGIN CERTIFICATE-----\n"
      "MIICWDCCAcGgAwIBAgIJAPuwTC6rEJsMMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV\n"
      "BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\n"
      "aWRnaXRzIFB0eSBMdGQwHhcNMTQwNDIzMjA1MDQwWhcNMTcwNDIyMjA1MDQwWjBF\n"
      "MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50\n"
      "ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\n"
      "gQDYK8imMuRi/03z0K1Zi0WnvfFHvwlYeyK9Na6XJYaUoIDAtB92kWdGMdAQhLci\n"
      "HnAjkXLI6W15OoV3gA/ElRZ1xUpxTMhjP6PyY5wqT5r6y8FxbiiFKKAnHmUcrgfV\n"
      "W28tQ+0rkLGMryRtrukXOgXBv7gcrmU7G1jC2a7WqmeI8QIDAQABo1AwTjAdBgNV\n"
      "HQ4EFgQUi3XVrMsIvg4fZbf6Vr5sp3Xaha8wHwYDVR0jBBgwFoAUi3XVrMsIvg4f\n"
      "Zbf6Vr5sp3Xaha8wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOBgQA76Hht\n"
      "ldY9avcTGSwbwoiuIqv0jTL1fHFnzy3RHMLDh+Lpvolc5DSrSJHCP5WuK0eeJXhr\n"
      "T5oQpHL9z/cCDLAKCKRa4uV0fhEdOWBqyR9p8y5jJtye72t6CuFUV5iqcpF4BH4f\n"
      "j2VNHwsSrJwkD4QUGlUtH7vwnQmyCFxZMmWAJg==\n"
      "-----END CERTIFICATE-----\n";
  return CertFromPEM(kCertPEM);
}

static bssl::UniquePtr<EVP_PKEY> GetTestKey() {
  static const char kKeyPEM[] =
      "-----BEGIN RSA PRIVATE KEY-----\n"
      "MIICXgIBAAKBgQDYK8imMuRi/03z0K1Zi0WnvfFHvwlYeyK9Na6XJYaUoIDAtB92\n"
      "kWdGMdAQhLciHnAjkXLI6W15OoV3gA/ElRZ1xUpxTMhjP6PyY5wqT5r6y8FxbiiF\n"
      "KKAnHmUcrgfVW28tQ+0rkLGMryRtrukXOgXBv7gcrmU7G1jC2a7WqmeI8QIDAQAB\n"
      "AoGBAIBy09Fd4DOq/Ijp8HeKuCMKTHqTW1xGHshLQ6jwVV2vWZIn9aIgmDsvkjCe\n"
      "i6ssZvnbjVcwzSoByhjN8ZCf/i15HECWDFFh6gt0P5z0MnChwzZmvatV/FXCT0j+\n"
      "WmGNB/gkehKjGXLLcjTb6dRYVJSCZhVuOLLcbWIV10gggJQBAkEA8S8sGe4ezyyZ\n"
      "m4e9r95g6s43kPqtj5rewTsUxt+2n4eVodD+ZUlCULWVNAFLkYRTBCASlSrm9Xhj\n"
      "QpmWAHJUkQJBAOVzQdFUaewLtdOJoPCtpYoY1zd22eae8TQEmpGOR11L6kbxLQsk\n"
      "aMly/DOnOaa82tqAGTdqDEZgSNmCeKKknmECQAvpnY8GUOVAubGR6c+W90iBuQLj\n"
      "LtFp/9ihd2w/PoDwrHZaoUYVcT4VSfJQog/k7kjE4MYXYWL8eEKg3WTWQNECQQDk\n"
      "104Wi91Umd1PzF0ijd2jXOERJU1wEKe6XLkYYNHWQAe5l4J4MWj9OdxFXAxIuuR/\n"
      "tfDwbqkta4xcux67//khAkEAvvRXLHTaa6VFzTaiiO8SaFsHV3lQyXOtMrBpB5jd\n"
      "moZWgjHvB2W9Ckn7sDqsPB+U2tyX0joDdQEyuiMECDY8oQ==\n"
      "-----END RSA PRIVATE KEY-----\n";
  return KeyFromPEM(kKeyPEM);
}

static bssl::UniquePtr<SSL_CTX> CreateContextWithTestCertificate(
    const SSL_METHOD *method) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(method));
  bssl::UniquePtr<X509> cert = GetTestCertificate();
  bssl::UniquePtr<EVP_PKEY> key = GetTestKey();
  if (!ctx || !cert || !key ||
      !SSL_CTX_use_certificate(ctx.get(), cert.get()) ||
      !SSL_CTX_use_PrivateKey(ctx.get(), key.get())) {
    return nullptr;
  }
  return ctx;
}

static bssl::UniquePtr<SSL_CTX> CreateContextWithCertificate(
    const SSL_METHOD *method, bssl::UniquePtr<X509> cert,
    bssl::UniquePtr<EVP_PKEY> key) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(method));
  if (!ctx || !cert || !key ||
      !SSL_CTX_use_certificate(ctx.get(), cert.get()) ||
      !SSL_CTX_use_PrivateKey(ctx.get(), key.get())) {
    return nullptr;
  }
  return ctx;
}

static bssl::UniquePtr<X509> GetECDSATestCertificate() {
  static const char kCertPEM[] =
      "-----BEGIN CERTIFICATE-----\n"
      "MIIBzzCCAXagAwIBAgIJANlMBNpJfb/rMAkGByqGSM49BAEwRTELMAkGA1UEBhMC\n"
      "QVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdp\n"
      "dHMgUHR5IEx0ZDAeFw0xNDA0MjMyMzIxNTdaFw0xNDA1MjMyMzIxNTdaMEUxCzAJ\n"
      "BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\n"
      "dCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATmK2ni\n"
      "v2Wfl74vHg2UikzVl2u3qR4NRvvdqakendy6WgHn1peoChj5w8SjHlbifINI2xYa\n"
      "HPUdfvGULUvPciLBo1AwTjAdBgNVHQ4EFgQUq4TSrKuV8IJOFngHVVdf5CaNgtEw\n"
      "HwYDVR0jBBgwFoAUq4TSrKuV8IJOFngHVVdf5CaNgtEwDAYDVR0TBAUwAwEB/zAJ\n"
      "BgcqhkjOPQQBA0gAMEUCIQDyoDVeUTo2w4J5m+4nUIWOcAZ0lVfSKXQA9L4Vh13E\n"
      "BwIgfB55FGohg/B6dGh5XxSZmmi08cueFV7mHzJSYV51yRQ=\n"
      "-----END CERTIFICATE-----\n";
  return CertFromPEM(kCertPEM);
}

static bssl::UniquePtr<EVP_PKEY> GetECDSATestKey() {
  static const char kKeyPEM[] =
      "-----BEGIN PRIVATE KEY-----\n"
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBw8IcnrUoEqc3VnJ\n"
      "TYlodwi1b8ldMHcO6NHJzgqLtGqhRANCAATmK2niv2Wfl74vHg2UikzVl2u3qR4N\n"
      "Rvvdqakendy6WgHn1peoChj5w8SjHlbifINI2xYaHPUdfvGULUvPciLB\n"
      "-----END PRIVATE KEY-----\n";
  return KeyFromPEM(kKeyPEM);
}

static bssl::UniquePtr<X509> GetED25519TestCertificate() {
  static const char kCertPEM[] =
      "-----BEGIN CERTIFICATE-----\n"
      "MIIBRDCB9wIUKI+32tShPulvafJa3xZvj29Z9xgwBQYDK2VwMEUxCzAJBgNVBAYT\n"
      "AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn\n"
      "aXRzIFB0eSBMdGQwHhcNMjMwNzE4MTg0NzU4WhcNMjMwNzE5MTg0NzU4WjBFMQsw\n"
      "CQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu\n"
      "ZXQgV2lkZ2l0cyBQdHkgTHRkMCowBQYDK2VwAyEAprAzqgxux8R4ZXaxn5mM/5E9\n"
      "0RNE59r47BJikdOoeUwwBQYDK2VwA0EAMELt0XRGFYo4qkWwOsoSYcdGYqlxVlf9\n"
      "AhTPaJ6SSzjv3n4r60wfe8Z2OPn415tcj2IIm42T64itI4OAX0aTCg==\n"
      "-----END CERTIFICATE-----\n";
  return CertFromPEM(kCertPEM);
}

static bssl::UniquePtr<EVP_PKEY> GetED25519TestKey() {
  static const char kKeyPEM[] =
      "-----BEGIN PRIVATE KEY-----\n"
      "MC4CAQAwBQYDK2VwBCIEIGPkz4xAobc5gtRidkHl+fxNLHfiWo3efRG2G8Z617yk\n"
      "-----END PRIVATE KEY-----\n";
  return KeyFromPEM(kKeyPEM);
}

static bssl::UniquePtr<CRYPTO_BUFFER> BufferFromPEM(const char *pem) {
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem, strlen(pem)));
  char *name, *header;
  uint8_t *data;
  long data_len;
  if (!PEM_read_bio(bio.get(), &name, &header, &data, &data_len)) {
    return nullptr;
  }
  OPENSSL_free(name);
  OPENSSL_free(header);

  auto ret = bssl::UniquePtr<CRYPTO_BUFFER>(
      CRYPTO_BUFFER_new(data, data_len, nullptr));
  OPENSSL_free(data);
  return ret;
}

static bssl::UniquePtr<CRYPTO_BUFFER> GetChainTestCertificateBuffer() {
  static const char kCertPEM[] =
      "-----BEGIN CERTIFICATE-----\n"
      "MIIC0jCCAbqgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwEQiBD\n"
      "QTAeFw0xNjAyMjgyMDI3MDNaFw0yNjAyMjUyMDI3MDNaMBgxFjAUBgNVBAMMDUNs\n"
      "aWVudCBDZXJ0IEEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDRvaz8\n"
      "CC/cshpCafJo4jLkHEoBqDLhdgFelJoAiQUyIqyWl2O7YHPnpJH+TgR7oelzNzt/\n"
      "kLRcH89M/TszB6zqyLTC4aqmvzKL0peD/jL2LWBucR0WXIvjA3zoRuF/x86+rYH3\n"
      "tHb+xs2PSs8EGL/Ev+ss+qTzTGEn26fuGNHkNw6tOwPpc+o8+wUtzf/kAthamo+c\n"
      "IDs2rQ+lP7+aLZTLeU/q4gcLutlzcK5imex5xy2jPkweq48kijK0kIzl1cPlA5d1\n"
      "z7C8jU50Pj9X9sQDJTN32j7UYRisJeeYQF8GaaN8SbrDI6zHgKzrRLyxDt/KQa9V\n"
      "iLeXANgZi+Xx9KgfAgMBAAGjLzAtMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYI\n"
      "KwYBBQUHAwEGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQBFEVbmYl+2RtNw\n"
      "rDftRDF1v2QUbcN2ouSnQDHxeDQdSgasLzT3ui8iYu0Rw2WWcZ0DV5e0ztGPhWq7\n"
      "AO0B120aFRMOY+4+bzu9Q2FFkQqc7/fKTvTDzIJI5wrMnFvUfzzvxh3OHWMYSs/w\n"
      "giq33hTKeHEq6Jyk3btCny0Ycecyc3yGXH10sizUfiHlhviCkDuESk8mFDwDDzqW\n"
      "ZF0IipzFbEDHoIxLlm3GQxpiLoEV4k8KYJp3R5KBLFyxM6UGPz8h72mIPCJp2RuK\n"
      "MYgF91UDvVzvnYm6TfseM2+ewKirC00GOrZ7rEcFvtxnKSqYf4ckqfNdSU1Y+RRC\n"
      "1ngWZ7Ih\n"
      "-----END CERTIFICATE-----\n";
  return BufferFromPEM(kCertPEM);
}

static bssl::UniquePtr<X509> X509FromBuffer(
    bssl::UniquePtr<CRYPTO_BUFFER> buffer) {
  if (!buffer) {
    return nullptr;
  }
  const uint8_t *derp = CRYPTO_BUFFER_data(buffer.get());
  return bssl::UniquePtr<X509>(
      d2i_X509(NULL, &derp, CRYPTO_BUFFER_len(buffer.get())));
}

static bssl::UniquePtr<X509> GetChainTestCertificate() {
  return X509FromBuffer(GetChainTestCertificateBuffer());
}

static bssl::UniquePtr<CRYPTO_BUFFER> GetChainTestIntermediateBuffer() {
  static const char kCertPEM[] =
      "-----BEGIN CERTIFICATE-----\n"
      "MIICwjCCAaqgAwIBAgICEAEwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJQyBS\n"
      "b290IENBMB4XDTE2MDIyODIwMjcwM1oXDTI2MDIyNTIwMjcwM1owDzENMAsGA1UE\n"
      "AwwEQiBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALsSCYmDip2D\n"
      "GkjFxw7ykz26JSjELkl6ArlYjFJ3aT/SCh8qbS4gln7RH8CPBd78oFdfhIKQrwtZ\n"
      "3/q21ykD9BAS3qHe2YdcJfm8/kWAy5DvXk6NXU4qX334KofBAEpgdA/igEFq1P1l\n"
      "HAuIfZCpMRfT+i5WohVsGi8f/NgpRvVaMONLNfgw57mz1lbtFeBEISmX0kbsuJxF\n"
      "Qj/Bwhi5/0HAEXG8e7zN4cEx0yPRvmOATRdVb/8dW2pwOHRJq9R5M0NUkIsTSnL7\n"
      "6N/z8hRAHMsV3IudC5Yd7GXW1AGu9a+iKU+Q4xcZCoj0DC99tL4VKujrV1kAeqsM\n"
      "cz5/dKzi6+cCAwEAAaMjMCEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n"
      "AQYwDQYJKoZIhvcNAQELBQADggEBAIIeZiEeNhWWQ8Y4D+AGDwqUUeG8NjCbKrXQ\n"
      "BlHg5wZ8xftFaiP1Dp/UAezmx2LNazdmuwrYB8lm3FVTyaPDTKEGIPS4wJKHgqH1\n"
      "QPDhqNm85ey7TEtI9oYjsNim/Rb+iGkIAMXaxt58SzxbjvP0kMr1JfJIZbic9vye\n"
      "NwIspMFIpP3FB8ywyu0T0hWtCQgL4J47nigCHpOu58deP88fS/Nyz/fyGVWOZ76b\n"
      "WhWwgM3P3X95fQ3d7oFPR/bVh0YV+Cf861INwplokXgXQ3/TCQ+HNXeAMWn3JLWv\n"
      "XFwk8owk9dq/kQGdndGgy3KTEW4ctPX5GNhf3LJ9Q7dLji4ReQ4=\n"
      "-----END CERTIFICATE-----\n";
  return BufferFromPEM(kCertPEM);
}

static bssl::UniquePtr<X509> GetChainTestIntermediate() {
  return X509FromBuffer(GetChainTestIntermediateBuffer());
}

static bssl::UniquePtr<EVP_PKEY> GetChainTestKey() {
  static const char kKeyPEM[] =
      "-----BEGIN PRIVATE KEY-----\n"
      "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRvaz8CC/cshpC\n"
      "afJo4jLkHEoBqDLhdgFelJoAiQUyIqyWl2O7YHPnpJH+TgR7oelzNzt/kLRcH89M\n"
      "/TszB6zqyLTC4aqmvzKL0peD/jL2LWBucR0WXIvjA3zoRuF/x86+rYH3tHb+xs2P\n"
      "Ss8EGL/Ev+ss+qTzTGEn26fuGNHkNw6tOwPpc+o8+wUtzf/kAthamo+cIDs2rQ+l\n"
      "P7+aLZTLeU/q4gcLutlzcK5imex5xy2jPkweq48kijK0kIzl1cPlA5d1z7C8jU50\n"
      "Pj9X9sQDJTN32j7UYRisJeeYQF8GaaN8SbrDI6zHgKzrRLyxDt/KQa9ViLeXANgZ\n"
      "i+Xx9KgfAgMBAAECggEBAK0VjSJzkyPaamcyTVSWjo7GdaBGcK60lk657RjR+lK0\n"
      "YJ7pkej4oM2hdsVZFsP8Cs4E33nXLa/0pDsRov/qrp0WQm2skwqGMC1I/bZ0WRPk\n"
      "wHaDrBBfESWnJDX/AGpVtlyOjPmgmK6J2usMPihQUDkKdAYrVWJePrMIxt1q6BMe\n"
      "iczs3qriMmtY3bUc4UyUwJ5fhDLjshHvfuIpYQyI6EXZM6dZksn9LylXJnigY6QJ\n"
      "HxOYO0BDwOsZ8yQ8J8afLk88i0GizEkgE1z3REtQUwgWfxr1WV/ud+T6/ZhSAgH9\n"
      "042mQvSFZnIUSEsmCvjhWuAunfxHKCTcAoYISWfzWpkCgYEA7gpf3HHU5Tn+CgUn\n"
      "1X5uGpG3DmcMgfeGgs2r2f/IIg/5Ac1dfYILiybL1tN9zbyLCJfcbFpWBc9hJL6f\n"
      "CPc5hUiwWFJqBJewxQkC1Ae/HakHbip+IZ+Jr0842O4BAArvixk4Lb7/N2Ct9sTE\n"
      "NJO6RtK9lbEZ5uK61DglHy8CS2UCgYEA4ZC1o36kPAMQBggajgnucb2yuUEelk0f\n"
      "AEr+GI32MGE+93xMr7rAhBoqLg4AITyIfEnOSQ5HwagnIHonBbv1LV/Gf9ursx8Z\n"
      "YOGbvT8zzzC+SU1bkDzdjAYnFQVGIjMtKOBJ3K07++ypwX1fr4QsQ8uKL8WSOWwt\n"
      "Z3Bym6XiZzMCgYADnhy+2OwHX85AkLt+PyGlPbmuelpyTzS4IDAQbBa6jcuW/2wA\n"
      "UE2km75VUXmD+u2R/9zVuLm99NzhFhSMqlUxdV1YukfqMfP5yp1EY6m/5aW7QuIP\n"
      "2MDa7TVL9rIFMiVZ09RKvbBbQxjhuzPQKL6X/PPspnhiTefQ+dl2k9xREQKBgHDS\n"
      "fMfGNEeAEKezrfSVqxphE9/tXms3L+ZpnCaT+yu/uEr5dTIAawKoQ6i9f/sf1/Sy\n"
      "xedsqR+IB+oKrzIDDWMgoJybN4pkZ8E5lzhVQIjFjKgFdWLzzqyW9z1gYfABQPlN\n"
      "FiS20WX0vgP1vcKAjdNrHzc9zyHBpgQzDmAj3NZZAoGBAI8vKCKdH7w3aL5CNkZQ\n"
      "2buIeWNA2HZazVwAGG5F2TU/LmXfRKnG6dX5bkU+AkBZh56jNZy//hfFSewJB4Kk\n"
      "buB7ERSdaNbO21zXt9FEA3+z0RfMd/Zv2vlIWOSB5nzl/7UKti3sribK6s9ZVLfi\n"
      "SxpiPQ8d/hmSGwn4ksrWUsJD\n"
      "-----END PRIVATE KEY-----\n";
  return KeyFromPEM(kKeyPEM);
}

static bool CompleteHandshakes(SSL *client, SSL *server) {
  // Drive both their handshakes to completion.
  for (;;) {
    int client_ret = SSL_do_handshake(client);
    int client_err = SSL_get_error(client, client_ret);
    if (client_err != SSL_ERROR_NONE && client_err != SSL_ERROR_WANT_READ &&
        client_err != SSL_ERROR_WANT_WRITE &&
        client_err != SSL_ERROR_PENDING_TICKET) {
      fprintf(stderr, "Client error: %s\n", SSL_error_description(client_err));
      return false;
    }

    int server_ret = SSL_do_handshake(server);
    int server_err = SSL_get_error(server, server_ret);
    if (server_err != SSL_ERROR_NONE && server_err != SSL_ERROR_WANT_READ &&
        server_err != SSL_ERROR_WANT_WRITE &&
        server_err != SSL_ERROR_PENDING_TICKET) {
      fprintf(stderr, "Server error: %s\n", SSL_error_description(server_err));
      return false;
    }

    if (client_ret == 1 && server_ret == 1) {
      break;
    }
  }

  return true;
}

static bool FlushNewSessionTickets(SSL *client, SSL *server) {
  // NewSessionTickets are deferred on the server to |SSL_write|, and clients do
  // not pick them up until |SSL_read|.
  for (;;) {
    int server_ret = SSL_write(server, nullptr, 0);
    int server_err = SSL_get_error(server, server_ret);
    // The server may either succeed (|server_ret| is zero) or block on write
    // (|server_ret| is -1 and |server_err| is |SSL_ERROR_WANT_WRITE|).
    if (server_ret > 0 ||
        (server_ret < 0 && server_err != SSL_ERROR_WANT_WRITE)) {
      fprintf(stderr, "Unexpected server result: %d %d\n", server_ret,
              server_err);
      return false;
    }

    int client_ret = SSL_read(client, nullptr, 0);
    int client_err = SSL_get_error(client, client_ret);
    // The client must always block on read.
    if (client_ret != -1 || client_err != SSL_ERROR_WANT_READ) {
      fprintf(stderr, "Unexpected client result: %d %d\n", client_ret,
              client_err);
      return false;
    }

    // The server flushed everything it had to write.
    if (server_ret == 0) {
      return true;
    }
  }
}

// CreateClientAndServer creates a client and server |SSL| objects whose |BIO|s
// are paired with each other. It does not run the handshake. The caller is
// expected to configure the objects and drive the handshake as needed.
static bool CreateClientAndServer(bssl::UniquePtr<SSL> *out_client,
                                  bssl::UniquePtr<SSL> *out_server,
                                  SSL_CTX *client_ctx, SSL_CTX *server_ctx) {
  bssl::UniquePtr<SSL> client(SSL_new(client_ctx)), server(SSL_new(server_ctx));
  if (!client || !server) {
    return false;
  }
  SSL_set_connect_state(client.get());
  SSL_set_accept_state(server.get());

  BIO *bio1, *bio2;
  if (!BIO_new_bio_pair(&bio1, 0, &bio2, 0)) {
    return false;
  }
  // SSL_set_bio takes ownership.
  SSL_set_bio(client.get(), bio1, bio1);
  SSL_set_bio(server.get(), bio2, bio2);

  *out_client = std::move(client);
  *out_server = std::move(server);
  return true;
}

struct ClientConfig {
  SSL_SESSION *session = nullptr;
  std::string servername;
  std::string verify_hostname;
  unsigned hostflags = 0;
  bool early_data = false;
};

static bool ConnectClientAndServer(bssl::UniquePtr<SSL> *out_client,
                                   bssl::UniquePtr<SSL> *out_server,
                                   SSL_CTX *client_ctx, SSL_CTX *server_ctx,
                                   const ClientConfig &config = ClientConfig(),
                                   bool shed_handshake_config = true) {
  bssl::UniquePtr<SSL> client, server;
  if (!CreateClientAndServer(&client, &server, client_ctx, server_ctx)) {
    return false;
  }
  if (config.early_data) {
    SSL_set_early_data_enabled(client.get(), 1);
  }
  if (config.session) {
    SSL_set_session(client.get(), config.session);
  }
  if (!config.servername.empty() &&
      !SSL_set_tlsext_host_name(client.get(), config.servername.c_str())) {
    return false;
  }
  if (!config.verify_hostname.empty()) {
    if (!SSL_set1_host(client.get(), config.verify_hostname.c_str())) {
      return false;
    }
    SSL_set_hostflags(client.get(), config.hostflags);
  }

  SSL_set_shed_handshake_config(client.get(), shed_handshake_config);
  SSL_set_shed_handshake_config(server.get(), shed_handshake_config);

  if (!CompleteHandshakes(client.get(), server.get())) {
    return false;
  }

  *out_client = std::move(client);
  *out_server = std::move(server);
  return true;
}

// Correct ID and name
#define TLS13_AES_128_GCM_SHA256_BYTES  ((const unsigned char *)"\x13\x01")
#define TLS13_CHACHA20_POLY1305_SHA256_BYTES ((const unsigned char *)"\x13\x03")
// Invalid ID
#define TLS13_AES_256_GCM_SHA384_BYTES  ((const unsigned char *)"\x13\x13")
TEST(SSLTest, FindingCipher) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
          CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  // Configure only TLS 1.3.
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));

  SCOPED_TRACE("TLS_AES_128_GCM_SHA256");
  const SSL_CIPHER *cipher1 = SSL_CIPHER_find(server.get(), TLS13_AES_128_GCM_SHA256_BYTES);
  ASSERT_TRUE(cipher1);
  EXPECT_STREQ("TLS_AES_128_GCM_SHA256", SSL_CIPHER_standard_name(cipher1));

  SCOPED_TRACE("TLS_CHACHA20_POLY1305_SHA256");
  const SSL_CIPHER *cipher2 = SSL_CIPHER_find(server.get(), TLS13_CHACHA20_POLY1305_SHA256_BYTES);
  ASSERT_TRUE(cipher2);
  EXPECT_STREQ("TLS_CHACHA20_POLY1305_SHA256", SSL_CIPHER_standard_name(cipher2));

  SCOPED_TRACE("TLS_AES_256_GCM_SHA384");
  const SSL_CIPHER *cipher3 = SSL_CIPHER_find(client.get(), TLS13_AES_256_GCM_SHA384_BYTES);
  ASSERT_FALSE(cipher3);
}

TEST(SSLTest, CheckSSLCipherInheritance) {
  // This configures SSL_CTX objects with default TLS 1.2 and 1.3 ciphersuites
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
          CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_2_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(server_ctx.get(), TLS1_2_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_3_VERSION));

  ASSERT_TRUE(SSL_CTX_set_ciphersuites(client_ctx.get(), "TLS_AES_128_GCM_SHA256"));
  ASSERT_TRUE(SSL_CTX_set_ciphersuites(server_ctx.get(), "TLS_AES_128_GCM_SHA256"));
  ASSERT_TRUE(SSL_CTX_set_cipher_list(client_ctx.get(), "TLS_RSA_WITH_AES_128_CBC_SHA"));
  ASSERT_TRUE(SSL_CTX_set_cipher_list(server_ctx.get(), "TLS_RSA_WITH_AES_128_CBC_SHA"));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(), server_ctx.get()));

  // Modify CTX ciphersuites
  ASSERT_TRUE(SSL_CTX_set_ciphersuites(client_ctx.get(), "TLS_AES_256_GCM_SHA384"));
  ASSERT_TRUE(SSL_CTX_set_ciphersuites(server_ctx.get(), "TLS_AES_256_GCM_SHA384"));
  ASSERT_TRUE(SSL_CTX_set_cipher_list(client_ctx.get(), "TLS_RSA_WITH_AES_256_CBC_SHA"));
  ASSERT_TRUE(SSL_CTX_set_cipher_list(server_ctx.get(), "TLS_RSA_WITH_AES_256_CBC_SHA"));

  // Ensure SSL object inherits initial CTX cipher suites
  STACK_OF(SSL_CIPHER) *client_ciphers = SSL_get_ciphers(client.get());
  STACK_OF(SSL_CIPHER) *server_ciphers = SSL_get_ciphers(server.get());
  ASSERT_TRUE(client_ciphers);
  ASSERT_TRUE(server_ciphers);
  ASSERT_EQ(sk_SSL_CIPHER_num(client_ciphers), 2u);
  ASSERT_EQ(sk_SSL_CIPHER_num(server_ciphers), 2u);
  const SSL_CIPHER *tls13_cipher = SSL_get_cipher_by_value(TLS1_3_CK_AES_128_GCM_SHA256 & 0xFFFF);
  const SSL_CIPHER *tls12_cipher = SSL_get_cipher_by_value(TLS1_CK_RSA_WITH_AES_128_SHA & 0xFFFF);
  ASSERT_TRUE(tls13_cipher);
  ASSERT_TRUE(tls12_cipher);

  ASSERT_TRUE(sk_SSL_CIPHER_find_awslc(client_ciphers, NULL, tls12_cipher));
  ASSERT_TRUE(sk_SSL_CIPHER_find_awslc(client_ciphers, NULL, tls13_cipher));
  ASSERT_TRUE(sk_SSL_CIPHER_find_awslc(server_ciphers, NULL, tls12_cipher));
  ASSERT_TRUE(sk_SSL_CIPHER_find_awslc(server_ciphers, NULL, tls13_cipher));

  SSL_set_shed_handshake_config(client.get(), 1);
  SSL_set_shed_handshake_config(server.get(), 1);

  ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));

  // Ensure we fall back to ctx once config is shed
  client_ciphers = SSL_get_ciphers(client.get());
  server_ciphers = SSL_get_ciphers(server.get());

  tls13_cipher = SSL_get_cipher_by_value(TLS1_3_CK_AES_256_GCM_SHA384 & 0xFFFF);
  tls12_cipher = SSL_get_cipher_by_value(TLS1_CK_RSA_WITH_AES_256_SHA & 0xFFFF);

  ASSERT_TRUE(sk_SSL_CIPHER_find_awslc(client_ciphers, NULL, tls13_cipher));
  ASSERT_TRUE(sk_SSL_CIPHER_find_awslc(server_ciphers, NULL, tls12_cipher));
}

TEST(SSLTest, SSLGetCiphersReturnsTLS13Default) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
          CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  // Configure only TLS 1.3.
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(server_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_3_VERSION));

  bssl::UniquePtr<SSL> client, server;
  // Have to ensure config is not shed per current implementation of SSL_get_ciphers.
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(), server_ctx.get(),
    ClientConfig(), false));

  // Ensure default TLS 1.3 Ciphersuites are present
  const SSL_CIPHER *cipher1 = SSL_get_cipher_by_value(TLS1_3_CK_AES_128_GCM_SHA256 & 0xFFFF);
  ASSERT_TRUE(cipher1);
  const SSL_CIPHER *cipher2 = SSL_get_cipher_by_value(TLS1_3_CK_AES_256_GCM_SHA384 & 0xFFFF);
  ASSERT_TRUE(cipher2);
  const SSL_CIPHER *cipher3 = SSL_get_cipher_by_value(TLS1_3_CK_CHACHA20_POLY1305_SHA256 & 0xFFFF);
  ASSERT_TRUE(cipher3);

  STACK_OF(SSL_CIPHER) *client_ciphers = SSL_get_ciphers(client.get());
  STACK_OF(SSL_CIPHER) *server_ciphers = SSL_get_ciphers(server.get());

  ASSERT_TRUE(sk_SSL_CIPHER_find_awslc(client_ciphers, NULL, cipher1));
  ASSERT_TRUE(sk_SSL_CIPHER_find_awslc(client_ciphers, NULL, cipher2));
  ASSERT_TRUE(sk_SSL_CIPHER_find_awslc(client_ciphers, NULL, cipher3));

  ASSERT_TRUE(sk_SSL_CIPHER_find_awslc(server_ciphers, NULL, cipher1));
  ASSERT_TRUE(sk_SSL_CIPHER_find_awslc(server_ciphers, NULL, cipher2));
  ASSERT_TRUE(sk_SSL_CIPHER_find_awslc(server_ciphers, NULL, cipher3));
}

TEST(SSLTest, TLS13ConfigCiphers) {
  // This configures SSL_CTX objects with default TLS 1.2 and 1.3 ciphersuites
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
          CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_2_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(server_ctx.get(), TLS1_2_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_3_VERSION));

  // Restrict TLS 1.3 ciphersuite
  ASSERT_TRUE(SSL_CTX_set_ciphersuites(client_ctx.get(), "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"));
  ASSERT_TRUE(SSL_CTX_set_ciphersuites(server_ctx.get(), "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(), server_ctx.get()));

  // Modify ciphersuites on the SSL object, this modifies ssl->config
  ASSERT_TRUE(SSL_set_ciphersuites(client.get(), "TLS_AES_256_GCM_SHA384"));
  ASSERT_TRUE(SSL_set_ciphersuites(server.get(), "TLS_AES_128_GCM_SHA256"));

  // Handshake should fail as config objects have no shared cipher.
  ASSERT_FALSE(CompleteHandshakes(client.get(), server.get()));
  ASSERT_EQ(ERR_GET_REASON(ERR_get_error()), SSL_R_NO_SHARED_CIPHER);

  bssl::UniquePtr<SSL> client2, server2;
  ASSERT_TRUE(CreateClientAndServer(&client2, &server2, client_ctx.get(), server_ctx.get()));

  // Modify ciphersuites on the SSL object, this modifies ssl->config
  ASSERT_TRUE(SSL_set_ciphersuites(client2.get(), "TLS_CHACHA20_POLY1305_SHA256"));
  ASSERT_TRUE(SSL_set_ciphersuites(server2.get(), "TLS_CHACHA20_POLY1305_SHA256"));

  ASSERT_TRUE(CompleteHandshakes(client2.get(), server2.get()));
  ASSERT_EQ(SSL_CIPHER_get_id(SSL_get_current_cipher(client2.get())), (uint32_t)TLS1_3_CK_CHACHA20_POLY1305_SHA256);
  ASSERT_EQ(SSL_CIPHER_get_id(SSL_get_current_cipher(server2.get())), (uint32_t)TLS1_3_CK_CHACHA20_POLY1305_SHA256);
}

TEST(SSLTest, TLS13ConfigCtxInteraction) {
  // This configures SSL_CTX objects with default TLS 1.2 and 1.3 ciphersuites
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
          CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_2_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(server_ctx.get(), TLS1_2_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_3_VERSION));

  // Restrict TLS 1.3 ciphersuite on the SSL_CTX objects
  ASSERT_TRUE(SSL_CTX_set_ciphersuites(client_ctx.get(), "TLS_AES_128_GCM_SHA256"));
  ASSERT_TRUE(SSL_CTX_set_ciphersuites(server_ctx.get(), "TLS_AES_128_GCM_SHA256"));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(), server_ctx.get()));

  // Modify TLS 1.3 ciphersuites for client's SSL object, but not server
  ASSERT_TRUE(SSL_set_ciphersuites(client.get(), "TLS_AES_256_GCM_SHA384"));

  // Handshake should fail as client SSL config and server CTX objects have no
  // shared TLS 1.3 cipher.
  ASSERT_FALSE(CompleteHandshakes(client.get(), server.get()));
  ASSERT_EQ(ERR_GET_REASON(ERR_get_error()), SSL_R_NO_SHARED_CIPHER);

  ERR_clear_error();

  bssl::UniquePtr<SSL> client2, server2;
  ASSERT_TRUE(CreateClientAndServer(&client2, &server2, client_ctx.get(), server_ctx.get()));

  // Modify TLS 1.3 ciphersuites for server2 SSL object, but not client
  ASSERT_TRUE(SSL_set_ciphersuites(server2.get(), "TLS_AES_256_GCM_SHA384"));

  // Handshake should fail as server SSL config and client CTX objects have no
  // shared TLS 1.3 cipher.
  ASSERT_FALSE(CompleteHandshakes(client2.get(), server2.get()));
  ASSERT_EQ(ERR_GET_REASON(ERR_get_error()), SSL_R_NO_SHARED_CIPHER);
}

TEST(SSLTest, TLS12ConfigCiphers) {
  // This configures SSL_CTX objects with default TLS 1.2 and 1.3 ciphersuites
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
          CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_2_VERSION));
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(server_ctx.get(), TLS1_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_2_VERSION));

  // Restrict TLS 1.2 ciphersuite
  ASSERT_TRUE(SSL_CTX_set_cipher_list(client_ctx.get(), "TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_256_GCM_SHA384"));
  ASSERT_TRUE(SSL_CTX_set_cipher_list(server_ctx.get(), "TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_256_GCM_SHA384"));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(), server_ctx.get()));

  // Modify ciphersuites on the SSL object and introduce mismatch, this modifies ssl->config
  ASSERT_TRUE(SSL_set_cipher_list(client.get(), "TLS_RSA_WITH_AES_256_CBC_SHA"));
  ASSERT_TRUE(SSL_set_cipher_list(server.get(), "TLS_RSA_WITH_AES_256_GCM_SHA384"));

  // Handshake should fail as config objects have no shared cipher.
  ASSERT_FALSE(CompleteHandshakes(client.get(), server.get()));
  ASSERT_EQ(ERR_GET_REASON(ERR_get_error()), SSL_R_NO_SHARED_CIPHER);

  ERR_clear_error();

  bssl::UniquePtr<SSL> client2, server2;
  ASSERT_TRUE(CreateClientAndServer(&client2, &server2, client_ctx.get(), server_ctx.get()));

  // Modify ciphersuites on the SSL object with a new third cipher, this modifies ssl->config
  ASSERT_TRUE(SSL_set_cipher_list(client2.get(), "TLS_RSA_WITH_AES_128_CBC_SHA"));
  ASSERT_TRUE(SSL_set_cipher_list(server2.get(), "TLS_RSA_WITH_AES_128_CBC_SHA"));

  ASSERT_TRUE(CompleteHandshakes(client2.get(), server2.get()));
  ASSERT_EQ(SSL_CIPHER_get_id(SSL_get_current_cipher(client2.get())), (uint32_t)TLS1_CK_RSA_WITH_AES_128_SHA);
  ASSERT_EQ(SSL_CIPHER_get_id(SSL_get_current_cipher(server2.get())), (uint32_t)TLS1_CK_RSA_WITH_AES_128_SHA);
}

TEST(SSLTest, TLS12ConfigCtxInteraction) {
  // This configures SSL_CTX objects with default TLS 1.2 and 1.3 ciphersuites
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
          CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_2_VERSION));
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(server_ctx.get(), TLS1_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_2_VERSION));

  // Restrict TLS 1.2 ciphersuites on the SSL_CTX objects
  ASSERT_TRUE(SSL_CTX_set_cipher_list(client_ctx.get(), "TLS_RSA_WITH_AES_256_CBC_SHA"));
  ASSERT_TRUE(SSL_CTX_set_cipher_list(server_ctx.get(), "TLS_RSA_WITH_AES_256_CBC_SHA"));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(), server_ctx.get()));

  // Modify TLS 1.2 ciphersuite for client's SSL object, but not server
  ASSERT_TRUE(SSL_set_cipher_list(client.get(), "TLS_RSA_WITH_AES_256_GCM_SHA384"));

  // Handshake should fail as client SSL config and server CTX objects have no
  // shared TLS 1.2 cipher.
  ASSERT_FALSE(CompleteHandshakes(client.get(), server.get()));
  ASSERT_EQ(ERR_GET_REASON(ERR_get_error()), SSL_R_NO_SHARED_CIPHER);

  ERR_clear_error();

  bssl::UniquePtr<SSL> client2, server2;
  ASSERT_TRUE(CreateClientAndServer(&client2, &server2, client_ctx.get(), server_ctx.get()));

  // Modify TLS 1.2 ciphersuites for server2 SSL object, but not client
  ASSERT_TRUE(SSL_set_cipher_list(server2.get(), "TLS_RSA_WITH_AES_256_GCM_SHA384"));

  // Handshake should fail as server SSL config and client CTX objects have no
  // shared TLS 1.2 cipher.
  ASSERT_FALSE(CompleteHandshakes(client2.get(), server2.get()));
  ASSERT_EQ(ERR_GET_REASON(ERR_get_error()), SSL_R_NO_SHARED_CIPHER);
}

TEST(SSLTest, SSLGetCiphersReturnsTLS13Custom) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
          CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  // Configure custom TLS 1.3 Ciphersuites
  SSL_CTX_set_ciphersuites(server_ctx.get(), "TLS_AES_128_GCM_SHA256");
  SSL_CTX_set_ciphersuites(client_ctx.get(), "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384");

  // Configure only TLS 1.3.
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(server_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_3_VERSION));

  bssl::UniquePtr<SSL> client, server;
  // Have to ensure config is not shed per current implementation of SSL_get_ciphers.
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(), server_ctx.get(),
    ClientConfig(), false));

  ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));
  // Ensure default TLS 1.3 Ciphersuites are present
  const SSL_CIPHER *cipher1 = SSL_get_cipher_by_value(TLS1_3_CK_AES_128_GCM_SHA256 & 0xFFFF);
  ASSERT_TRUE(cipher1);
  const SSL_CIPHER *cipher2 = SSL_get_cipher_by_value(TLS1_3_CK_AES_256_GCM_SHA384 & 0xFFFF);
  ASSERT_TRUE(cipher2);
  const SSL_CIPHER *cipher3 = SSL_get_cipher_by_value(TLS1_3_CK_CHACHA20_POLY1305_SHA256 & 0xFFFF);
  ASSERT_TRUE(cipher3);

  STACK_OF(SSL_CIPHER) *client_ciphers = SSL_get_ciphers(client.get());
  STACK_OF(SSL_CIPHER) *server_ciphers = SSL_get_ciphers(server.get());

  ASSERT_TRUE(sk_SSL_CIPHER_find_awslc(client_ciphers, NULL, cipher1));
  ASSERT_TRUE(sk_SSL_CIPHER_find_awslc(client_ciphers, NULL, cipher2));
  ASSERT_FALSE(sk_SSL_CIPHER_find_awslc(client_ciphers, NULL, cipher3));

  ASSERT_TRUE(sk_SSL_CIPHER_find_awslc(server_ciphers, NULL, cipher1));
  ASSERT_FALSE(sk_SSL_CIPHER_find_awslc(server_ciphers, NULL, cipher2));
  ASSERT_FALSE(sk_SSL_CIPHER_find_awslc(server_ciphers, NULL, cipher3));
}

TEST(SSLTest, GetClientCiphersAfterHandshakeFailure1_3) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx = CreateContextWithTestCertificate(TLS_method());

  // configure client to add fake ciphersuite
  SSL_CTX_set_grease_enabled(client_ctx.get(), 1);

  // There will be no cipher match, handshake will not succeed.
  ASSERT_TRUE(SSL_CTX_set_ciphersuites(client_ctx.get(),
                                       "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"));
  ASSERT_TRUE(SSL_CTX_set_ciphersuites(server_ctx.get(),
                                               "TLS_AES_128_GCM_SHA256"));

  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server,
                                    client_ctx.get(), server_ctx.get()));

  const unsigned char *tmp = nullptr;
  // Handshake not completed, getting ciphers should fail
  ASSERT_FALSE(SSL_client_hello_get0_ciphers(client.get(), &tmp));
  ASSERT_FALSE(SSL_client_hello_get0_ciphers(server.get(), &tmp));
  ASSERT_FALSE(tmp);

  // This should fail, but should be able to inspect client ciphers still
  ASSERT_FALSE(CompleteHandshakes(client.get(), server.get()));

  ASSERT_EQ(SSL_client_hello_get0_ciphers(client.get(), nullptr), (size_t) 0);

  const unsigned char expected_cipher_bytes[] = {0x13, 0x02, 0x13, 0x03};
  const unsigned char *p = nullptr;

  // Expected size is 2 bytes more than |expected_cipher_bytes| to account for
  // grease value
  ASSERT_EQ(SSL_client_hello_get0_ciphers(server.get(), &p),
            sizeof(expected_cipher_bytes) + 2);

  // Grab the first 2 bytes and check grease value
  uint16_t grease_val = CRYPTO_load_u16_be(p);
  ASSERT_FALSE(SSL_get_cipher_by_value(grease_val));

  // Sanity check for first cipher ID after grease value
  uint16_t cipher_val = CRYPTO_load_u16_be(p+2);
  ASSERT_TRUE(SSL_get_cipher_by_value((cipher_val)));

  // Check order and validity of the rest of the client cipher suites,
  // excluding the grease value (2nd byte onwards)
  ASSERT_EQ(Bytes(expected_cipher_bytes, sizeof(expected_cipher_bytes)),
            Bytes(p+2, sizeof(expected_cipher_bytes)));

  // Parsed ciphersuite list should only have 2 valid ciphersuites as configured
  // (grease value should not be included). Even though the handshake fails,
  // client cipher data should be available through the server SSL object.
  ASSERT_TRUE(sk_SSL_CIPHER_num(server.get()->client_cipher_suites.get()) == 2);
}

TEST(SSLTest, GetClientCiphers1_3) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx = CreateContextWithTestCertificate(TLS_method());

  // configure client to add fake ciphersuite
  SSL_CTX_set_grease_enabled(client_ctx.get(), 1);

  ASSERT_TRUE(SSL_CTX_set_ciphersuites(client_ctx.get(),
                                       "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"));

  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server,
                                    client_ctx.get(), server_ctx.get()));

  const unsigned char *tmp = nullptr;
  // Handshake not completed, getting ciphers should fail
  ASSERT_FALSE(SSL_client_hello_get0_ciphers(client.get(), &tmp));
  ASSERT_FALSE(SSL_client_hello_get0_ciphers(server.get(), &tmp));
  ASSERT_FALSE(tmp);

  ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));

  ASSERT_EQ(SSL_client_hello_get0_ciphers(client.get(), nullptr), (size_t) 0);

  const unsigned char expected_cipher_bytes[] = {0x13, 0x01, 0x13, 0x02, 0x13, 0x03};
  const unsigned char *p = nullptr;

  // Expected size is 2 bytes more than |expected_cipher_bytes| to account for
  // grease value
  ASSERT_EQ(SSL_client_hello_get0_ciphers(server.get(), &p),
            sizeof(expected_cipher_bytes) + 2);

  // Grab the first 2 bytes and check grease value
  uint16_t grease_val = CRYPTO_load_u16_be(p);
  ASSERT_FALSE(SSL_get_cipher_by_value(grease_val));

  // Sanity check for first cipher ID after grease value
  uint16_t cipher_val = CRYPTO_load_u16_be(p+2);
  ASSERT_TRUE(SSL_get_cipher_by_value((cipher_val)));

  // Check order and validity of the rest of the client cipher suites,
  // excluding the grease value (2nd byte onwards)
  ASSERT_EQ(Bytes(expected_cipher_bytes, sizeof(expected_cipher_bytes)),
            Bytes(p+2, sizeof(expected_cipher_bytes)));

  // Parsed ciphersuite list should only have 3 valid ciphersuites as configured
  // (grease value should not be included)
  ASSERT_TRUE(sk_SSL_CIPHER_num(server.get()->client_cipher_suites.get()) == 3);
}

TEST(SSLTest, GetClientCiphers1_2) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
          CreateContextWithTestCertificate(TLS_method());

  // configure client to add fake ciphersuite
  SSL_CTX_set_grease_enabled(client_ctx.get(), 1);

  ASSERT_TRUE(SSL_CTX_set_cipher_list(client_ctx.get(),
                                      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"));
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_2_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_2_VERSION));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server,
                                    client_ctx.get(), server_ctx.get()));

  const unsigned char *tmp = nullptr;
  // Handshake not completed, getting ciphers should fail
  ASSERT_FALSE(SSL_client_hello_get0_ciphers(client.get(), &tmp));
  ASSERT_FALSE(SSL_client_hello_get0_ciphers(server.get(), &tmp));
  ASSERT_FALSE(tmp);

  ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));

  ASSERT_EQ(SSL_client_hello_get0_ciphers(client.get(), nullptr), (size_t) 0);

  const unsigned char expected_cipher_bytes[] = {0xC0, 0x2C, 0xC0, 0x13};
  const unsigned char *p = nullptr;

  // Expected size is 2 bytes more than |expected_cipher_bytes| to account for
  // grease value
  ASSERT_EQ(SSL_client_hello_get0_ciphers(server.get(), &p),
            sizeof(expected_cipher_bytes) + 2);

  // Grab the first 2 bytes and check grease value
  uint16_t grease_val = CRYPTO_load_u16_be(p);
  ASSERT_FALSE(SSL_get_cipher_by_value(grease_val));

  // Sanity check for first cipher ID after grease value
  uint16_t cipher_val = CRYPTO_load_u16_be(p+2);
  ASSERT_TRUE(SSL_get_cipher_by_value((cipher_val)));

  // Check order and validity of the rest of the client cipher suites,
  // excluding the grease value (2nd byte onwards)
  ASSERT_EQ(Bytes(expected_cipher_bytes, sizeof(expected_cipher_bytes)),
            Bytes(p+2, sizeof(expected_cipher_bytes)));

  // Parsed ciphersuite list should only have 2 valid ciphersuites as configured
  // (grease value should not be included)
  ASSERT_TRUE(sk_SSL_CIPHER_num(server.get()->client_cipher_suites.get()) == 2);
}

static bssl::UniquePtr<SSL_SESSION> g_last_session;

static int SaveLastSession(SSL *ssl, SSL_SESSION *session) {
  // Save the most recent session.
  g_last_session.reset(session);
  return 1;
}

static bssl::UniquePtr<SSL_SESSION> CreateClientSession(
    SSL_CTX *client_ctx, SSL_CTX *server_ctx,
    const ClientConfig &config = ClientConfig()) {
  g_last_session = nullptr;
  SSL_CTX_sess_set_new_cb(client_ctx, SaveLastSession);

  // Connect client and server to get a session.
  bssl::UniquePtr<SSL> client, server;
  if (!ConnectClientAndServer(&client, &server, client_ctx, server_ctx,
                              config) ||
      !FlushNewSessionTickets(client.get(), server.get())) {
    fprintf(stderr, "Failed to connect client and server.\n");
    return nullptr;
  }

  SSL_CTX_sess_set_new_cb(client_ctx, nullptr);

  if (!g_last_session) {
    fprintf(stderr, "Client did not receive a session.\n");
    return nullptr;
  }
  return std::move(g_last_session);
}

static void SetUpExpectedNewCodePoint(SSL_CTX *ctx) {
  SSL_CTX_set_select_certificate_cb(
      ctx,
      [](const SSL_CLIENT_HELLO *client_hello) -> ssl_select_cert_result_t {
        const uint8_t *data;
        size_t len;
        if (!SSL_early_callback_ctx_extension_get(
                client_hello, TLSEXT_TYPE_application_settings, &data,
                &len)) {
          ADD_FAILURE() << "Could not find alps new codepoint.";
          return ssl_select_cert_error;
        }
        return ssl_select_cert_success;
      });
}

static void SetUpExpectedOldCodePoint(SSL_CTX *ctx) {
  SSL_CTX_set_select_certificate_cb(
      ctx,
      [](const SSL_CLIENT_HELLO *client_hello) -> ssl_select_cert_result_t {
        const uint8_t *data;
        size_t len;
        if (!SSL_early_callback_ctx_extension_get(
                client_hello, TLSEXT_TYPE_application_settings_old, &data,
                &len)) {
          ADD_FAILURE() << "Could not find alps old codepoint.";
          return ssl_select_cert_error;
        }
        return ssl_select_cert_success;
      });
}

// Test that |SSL_get_client_CA_list| echoes back the configured parameter even
// before configuring as a server.
TEST(SSLTest, ClientCAList) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);

  bssl::UniquePtr<X509_NAME> name(X509_NAME_new());
  ASSERT_TRUE(name);

  bssl::UniquePtr<X509_NAME> name_dup(X509_NAME_dup(name.get()));
  ASSERT_TRUE(name_dup);

  bssl::UniquePtr<STACK_OF(X509_NAME)> stack(sk_X509_NAME_new_null());
  ASSERT_TRUE(stack);
  ASSERT_TRUE(PushToStack(stack.get(), std::move(name_dup)));

  // |SSL_set_client_CA_list| takes ownership.
  SSL_set_client_CA_list(ssl.get(), stack.release());

  STACK_OF(X509_NAME) *result = SSL_get_client_CA_list(ssl.get());
  ASSERT_TRUE(result);
  ASSERT_EQ(1u, sk_X509_NAME_num(result));
  EXPECT_EQ(0, X509_NAME_cmp(sk_X509_NAME_value(result, 0), name.get()));
}

TEST(SSLTest, AddClientCA) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);

  bssl::UniquePtr<X509> cert1 = GetTestCertificate();
  bssl::UniquePtr<X509> cert2 = GetChainTestCertificate();
  ASSERT_TRUE(cert1 && cert2);
  X509_NAME *name1 = X509_get_subject_name(cert1.get());
  X509_NAME *name2 = X509_get_subject_name(cert2.get());

  EXPECT_EQ(0u, sk_X509_NAME_num(SSL_get_client_CA_list(ssl.get())));

  ASSERT_TRUE(SSL_add_client_CA(ssl.get(), cert1.get()));
  ASSERT_TRUE(SSL_add_client_CA(ssl.get(), cert2.get()));

  STACK_OF(X509_NAME) *list = SSL_get_client_CA_list(ssl.get());
  ASSERT_EQ(2u, sk_X509_NAME_num(list));
  EXPECT_EQ(0, X509_NAME_cmp(sk_X509_NAME_value(list, 0), name1));
  EXPECT_EQ(0, X509_NAME_cmp(sk_X509_NAME_value(list, 1), name2));

  ASSERT_TRUE(SSL_add_client_CA(ssl.get(), cert1.get()));

  list = SSL_get_client_CA_list(ssl.get());
  ASSERT_EQ(3u, sk_X509_NAME_num(list));
  EXPECT_EQ(0, X509_NAME_cmp(sk_X509_NAME_value(list, 0), name1));
  EXPECT_EQ(0, X509_NAME_cmp(sk_X509_NAME_value(list, 1), name2));
  EXPECT_EQ(0, X509_NAME_cmp(sk_X509_NAME_value(list, 2), name1));
}

struct ECHConfigParams {
  uint16_t version = TLSEXT_TYPE_encrypted_client_hello;
  uint16_t config_id = 1;
  std::string public_name = "example.com";
  const EVP_HPKE_KEY *key = nullptr;
  // kem_id, if zero, takes its value from |key|.
  uint16_t kem_id = 0;
  // public_key, if empty takes its value from |key|.
  std::vector<uint8_t> public_key;
  size_t max_name_len = 16;
  // cipher_suites is a list of code points which should contain pairs of KDF
  // and AEAD IDs.
  std::vector<uint16_t> cipher_suites = {EVP_HPKE_HKDF_SHA256,
                                         EVP_HPKE_AES_128_GCM};
  std::vector<uint8_t> extensions;
};

// MakeECHConfig serializes an ECHConfig from |params| and writes it to
// |*out|.
bool MakeECHConfig(std::vector<uint8_t> *out, const ECHConfigParams &params) {
  uint16_t kem_id = params.kem_id == 0
                        ? EVP_HPKE_KEM_id(EVP_HPKE_KEY_kem(params.key))
                        : params.kem_id;
  std::vector<uint8_t> public_key = params.public_key;
  if (public_key.empty()) {
    public_key.resize(EVP_HPKE_MAX_PUBLIC_KEY_LENGTH);
    size_t len;
    if (!EVP_HPKE_KEY_public_key(params.key, public_key.data(), &len,
                                 public_key.size())) {
      return false;
    }
    public_key.resize(len);
  }

  bssl::ScopedCBB cbb;
  CBB contents, child;
  if (!CBB_init(cbb.get(), 64) || !CBB_add_u16(cbb.get(), params.version) ||
      !CBB_add_u16_length_prefixed(cbb.get(), &contents) ||
      !CBB_add_u8(&contents, params.config_id) ||
      !CBB_add_u16(&contents, kem_id) ||
      !CBB_add_u16_length_prefixed(&contents, &child) ||
      !CBB_add_bytes(&child, public_key.data(), public_key.size()) ||
      !CBB_add_u16_length_prefixed(&contents, &child)) {
    return false;
  }
  for (uint16_t cipher_suite : params.cipher_suites) {
    if (!CBB_add_u16(&child, cipher_suite)) {
      return false;
    }
  }
  if (!CBB_add_u8(&contents, params.max_name_len) ||
      !CBB_add_u8_length_prefixed(&contents, &child) ||
      !CBB_add_bytes(
          &child, reinterpret_cast<const uint8_t *>(params.public_name.data()),
          params.public_name.size()) ||
      !CBB_add_u16_length_prefixed(&contents, &child) ||
      !CBB_add_bytes(&child, params.extensions.data(),
                     params.extensions.size()) ||
      !CBB_flush(cbb.get())) {
    return false;
  }

  out->assign(CBB_data(cbb.get()), CBB_data(cbb.get()) + CBB_len(cbb.get()));
  return true;
}

static bssl::UniquePtr<SSL_ECH_KEYS> MakeTestECHKeys(uint8_t config_id = 1) {
  bssl::ScopedEVP_HPKE_KEY key;
  uint8_t *ech_config;
  size_t ech_config_len;
  if (!EVP_HPKE_KEY_generate(key.get(), EVP_hpke_x25519_hkdf_sha256()) ||
      !SSL_marshal_ech_config(&ech_config, &ech_config_len, config_id,
                              key.get(), "public.example", 16)) {
    return nullptr;
  }
  bssl::UniquePtr<uint8_t> free_ech_config(ech_config);

  // Install a non-retry config.
  bssl::UniquePtr<SSL_ECH_KEYS> keys(SSL_ECH_KEYS_new());
  if (!keys || !SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1, ech_config,
                                 ech_config_len, key.get())) {
    return nullptr;
  }
  return keys;
}

static bool InstallECHConfigList(SSL *client, const SSL_ECH_KEYS *keys) {
  uint8_t *ech_config_list;
  size_t ech_config_list_len;
  if (!SSL_ECH_KEYS_marshal_retry_configs(keys, &ech_config_list,
                                          &ech_config_list_len)) {
    return false;
  }
  bssl::UniquePtr<uint8_t> free_ech_config_list(ech_config_list);
  return SSL_set1_ech_config_list(client, ech_config_list, ech_config_list_len);
}

// Test that |SSL_marshal_ech_config| and |SSL_ECH_KEYS_marshal_retry_configs|
// output values as expected.
TEST(SSLTest, MarshalECHConfig) {
  static const uint8_t kPrivateKey[X25519_PRIVATE_KEY_LEN] = {
      0xbc, 0xb5, 0x51, 0x29, 0x31, 0x10, 0x30, 0xc9, 0xed, 0x26, 0xde,
      0xd4, 0xb3, 0xdf, 0x3a, 0xce, 0x06, 0x8a, 0xee, 0x17, 0xab, 0xce,
      0xd7, 0xdb, 0xf3, 0x11, 0xe5, 0xa8, 0xf3, 0xb1, 0x8e, 0x24};
  bssl::ScopedEVP_HPKE_KEY key;
  ASSERT_TRUE(EVP_HPKE_KEY_init(key.get(), EVP_hpke_x25519_hkdf_sha256(),
                                kPrivateKey, sizeof(kPrivateKey)));

  static const uint8_t kECHConfig[] = {
      // version
      0xfe, 0x0d,
      // length
      0x00, 0x41,
      // contents.config_id
      0x01,
      // contents.kem_id
      0x00, 0x20,
      // contents.public_key
      0x00, 0x20, 0xa6, 0x9a, 0x41, 0x48, 0x5d, 0x32, 0x96, 0xa4, 0xe0, 0xc3,
      0x6a, 0xee, 0xf6, 0x63, 0x0f, 0x59, 0x32, 0x6f, 0xdc, 0xff, 0x81, 0x29,
      0x59, 0xa5, 0x85, 0xd3, 0x9b, 0x3b, 0xde, 0x98, 0x55, 0x5c,
      // contents.cipher_suites
      0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x03,
      // contents.maximum_name_length
      0x10,
      // contents.public_name
      0x0e, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2e, 0x65, 0x78, 0x61, 0x6d,
      0x70, 0x6c, 0x65,
      // contents.extensions
      0x00, 0x00};
  uint8_t *ech_config;
  size_t ech_config_len;
  ASSERT_TRUE(SSL_marshal_ech_config(&ech_config, &ech_config_len,
                                     /*config_id=*/1, key.get(),
                                     "public.example", 16));
  bssl::UniquePtr<uint8_t> free_ech_config(ech_config);
  EXPECT_EQ(Bytes(kECHConfig), Bytes(ech_config, ech_config_len));

  // Generate a second ECHConfig.
  bssl::ScopedEVP_HPKE_KEY key2;
  ASSERT_TRUE(EVP_HPKE_KEY_generate(key2.get(), EVP_hpke_x25519_hkdf_sha256()));
  uint8_t *ech_config2;
  size_t ech_config2_len;
  ASSERT_TRUE(SSL_marshal_ech_config(&ech_config2, &ech_config2_len,
                                     /*config_id=*/2, key2.get(),
                                     "public.example", 16));
  bssl::UniquePtr<uint8_t> free_ech_config2(ech_config2);

  // Install both ECHConfigs in an |SSL_ECH_KEYS|.
  bssl::UniquePtr<SSL_ECH_KEYS> keys(SSL_ECH_KEYS_new());
  ASSERT_TRUE(keys);
  ASSERT_TRUE(SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1, ech_config,
                               ech_config_len, key.get()));
  ASSERT_TRUE(SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1, ech_config2,
                               ech_config2_len, key2.get()));

  // The ECHConfigList should be correctly serialized.
  uint8_t *ech_config_list;
  size_t ech_config_list_len;
  ASSERT_TRUE(SSL_ECH_KEYS_marshal_retry_configs(keys.get(), &ech_config_list,
                                                 &ech_config_list_len));
  bssl::UniquePtr<uint8_t> free_ech_config_list(ech_config_list);

  // ECHConfigList is just the concatenation with a length prefix.
  size_t len = ech_config_len + ech_config2_len;
  std::vector<uint8_t> expected = {uint8_t(len >> 8), uint8_t(len)};
  expected.insert(expected.end(), ech_config, ech_config + ech_config_len);
  expected.insert(expected.end(), ech_config2, ech_config2 + ech_config2_len);
  EXPECT_EQ(Bytes(expected), Bytes(ech_config_list, ech_config_list_len));
}

TEST(SSLTest, ECHHasDuplicateConfigID) {
  const struct {
    std::vector<uint8_t> ids;
    bool has_duplicate;
  } kTests[] = {
      {{}, false},
      {{1}, false},
      {{1, 2, 3, 255}, false},
      {{1, 2, 3, 1}, true},
  };
  for (const auto &test : kTests) {
    bssl::UniquePtr<SSL_ECH_KEYS> keys(SSL_ECH_KEYS_new());
    ASSERT_TRUE(keys);
    for (const uint8_t id : test.ids) {
      bssl::ScopedEVP_HPKE_KEY key;
      ASSERT_TRUE(
          EVP_HPKE_KEY_generate(key.get(), EVP_hpke_x25519_hkdf_sha256()));
      uint8_t *ech_config;
      size_t ech_config_len;
      ASSERT_TRUE(SSL_marshal_ech_config(&ech_config, &ech_config_len, id,
                                         key.get(), "public.example", 16));
      bssl::UniquePtr<uint8_t> free_ech_config(ech_config);
      ASSERT_TRUE(SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1,
                                   ech_config, ech_config_len, key.get()));
    }

    EXPECT_EQ(test.has_duplicate ? 1 : 0,
              SSL_ECH_KEYS_has_duplicate_config_id(keys.get()));
  }
}

// Test that |SSL_ECH_KEYS_add| checks consistency between the public and
// private key.
TEST(SSLTest, ECHKeyConsistency) {
  bssl::UniquePtr<SSL_ECH_KEYS> keys(SSL_ECH_KEYS_new());
  ASSERT_TRUE(keys);
  bssl::ScopedEVP_HPKE_KEY key;
  ASSERT_TRUE(EVP_HPKE_KEY_generate(key.get(), EVP_hpke_x25519_hkdf_sha256()));
  uint8_t public_key[EVP_HPKE_MAX_PUBLIC_KEY_LENGTH];
  size_t public_key_len;
  ASSERT_TRUE(EVP_HPKE_KEY_public_key(key.get(), public_key, &public_key_len,
                                      sizeof(public_key)));

  // Adding an ECHConfig with the matching public key succeeds.
  ECHConfigParams params;
  params.key = key.get();
  std::vector<uint8_t> ech_config;
  ASSERT_TRUE(MakeECHConfig(&ech_config, params));
  EXPECT_TRUE(SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1,
                               ech_config.data(), ech_config.size(),
                               key.get()));

  // Adding an ECHConfig with the wrong public key is an error.
  bssl::ScopedEVP_HPKE_KEY wrong_key;
  ASSERT_TRUE(
      EVP_HPKE_KEY_generate(wrong_key.get(), EVP_hpke_x25519_hkdf_sha256()));
  EXPECT_FALSE(SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1,
                                ech_config.data(), ech_config.size(),
                                wrong_key.get()));

  // Adding an ECHConfig with a truncated public key is an error.
  ECHConfigParams truncated;
  truncated.key = key.get();
  truncated.public_key.assign(public_key, public_key + public_key_len - 1);
  ASSERT_TRUE(MakeECHConfig(&ech_config, truncated));
  EXPECT_FALSE(SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1,
                                ech_config.data(), ech_config.size(),
                                key.get()));

  // Adding an ECHConfig with the right public key, but wrong KEM ID, is an
  // error.
  ECHConfigParams wrong_kem;
  wrong_kem.key = key.get();
  wrong_kem.kem_id = 0x0010;  // DHKEM(P-256, HKDF-SHA256)
  ASSERT_TRUE(MakeECHConfig(&ech_config, wrong_kem));
  EXPECT_FALSE(SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1,
                                ech_config.data(), ech_config.size(),
                                key.get()));
}

// Test that |SSL_CTX_set1_ech_keys| fails when the config list
// has no retry configs.
TEST(SSLTest, ECHServerConfigsWithoutRetryConfigs) {
  bssl::ScopedEVP_HPKE_KEY key;
  ASSERT_TRUE(EVP_HPKE_KEY_generate(key.get(), EVP_hpke_x25519_hkdf_sha256()));
  uint8_t *ech_config;
  size_t ech_config_len;
  ASSERT_TRUE(SSL_marshal_ech_config(&ech_config, &ech_config_len,
                                     /*config_id=*/1, key.get(),
                                     "public.example", 16));
  bssl::UniquePtr<uint8_t> free_ech_config(ech_config);

  // Install a non-retry config.
  bssl::UniquePtr<SSL_ECH_KEYS> keys(SSL_ECH_KEYS_new());
  ASSERT_TRUE(keys);
  ASSERT_TRUE(SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/0, ech_config,
                               ech_config_len, key.get()));

  // |keys| has no retry configs.
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  EXPECT_FALSE(SSL_CTX_set1_ech_keys(ctx.get(), keys.get()));

  // Add the same ECHConfig to the list, but this time mark it as a retry
  // config.
  ASSERT_TRUE(SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1, ech_config,
                               ech_config_len, key.get()));
  EXPECT_TRUE(SSL_CTX_set1_ech_keys(ctx.get(), keys.get()));
}

// Test that the server APIs reject ECHConfigs with unsupported features.
TEST(SSLTest, UnsupportedECHConfig) {
  bssl::UniquePtr<SSL_ECH_KEYS> keys(SSL_ECH_KEYS_new());
  ASSERT_TRUE(keys);
  bssl::ScopedEVP_HPKE_KEY key;
  ASSERT_TRUE(EVP_HPKE_KEY_generate(key.get(), EVP_hpke_x25519_hkdf_sha256()));

  // Unsupported versions are rejected.
  ECHConfigParams unsupported_version;
  unsupported_version.version = 0xffff;
  unsupported_version.key = key.get();
  std::vector<uint8_t> ech_config;
  ASSERT_TRUE(MakeECHConfig(&ech_config, unsupported_version));
  EXPECT_FALSE(SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1,
                                ech_config.data(), ech_config.size(),
                                key.get()));

  // Unsupported cipher suites are rejected. (We only support HKDF-SHA256.)
  ECHConfigParams unsupported_kdf;
  unsupported_kdf.key = key.get();
  unsupported_kdf.cipher_suites = {0x002 /* HKDF-SHA384 */,
                                   EVP_HPKE_AES_128_GCM};
  ASSERT_TRUE(MakeECHConfig(&ech_config, unsupported_kdf));
  EXPECT_FALSE(SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1,
                                ech_config.data(), ech_config.size(),
                                key.get()));
  ECHConfigParams unsupported_aead;
  unsupported_aead.key = key.get();
  unsupported_aead.cipher_suites = {EVP_HPKE_HKDF_SHA256, 0xffff};
  ASSERT_TRUE(MakeECHConfig(&ech_config, unsupported_aead));
  EXPECT_FALSE(SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1,
                                ech_config.data(), ech_config.size(),
                                key.get()));


  // Unsupported extensions are rejected.
  ECHConfigParams extensions;
  extensions.key = key.get();
  extensions.extensions = {0x00, 0x01, 0x00, 0x00};
  ASSERT_TRUE(MakeECHConfig(&ech_config, extensions));
  EXPECT_FALSE(SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1,
                                ech_config.data(), ech_config.size(),
                                key.get()));

  // Invalid public names are rejected.
  ECHConfigParams invalid_public_name;
  invalid_public_name.key = key.get();
  invalid_public_name.public_name = "dns_names_have_no_underscores.example";
  ASSERT_TRUE(MakeECHConfig(&ech_config, invalid_public_name));
  EXPECT_FALSE(SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1,
                                ech_config.data(), ech_config.size(),
                                key.get()));
}

// Test that |SSL_get_client_random| reports the correct value on both client
// and server in ECH. The client sends two different random values. When ECH is
// accepted, we should report the inner one.
TEST(SSLTest, ECHClientRandomsMatch) {
  bssl::UniquePtr<SSL_CTX> server_ctx =
      CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(server_ctx);
  bssl::UniquePtr<SSL_ECH_KEYS> keys = MakeTestECHKeys();
  ASSERT_TRUE(keys);
  ASSERT_TRUE(SSL_CTX_set1_ech_keys(server_ctx.get(), keys.get()));

  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(client_ctx);
  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(),
                                    server_ctx.get()));
  ASSERT_TRUE(InstallECHConfigList(client.get(), keys.get()));
  ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));

  EXPECT_TRUE(SSL_ech_accepted(client.get()));
  EXPECT_TRUE(SSL_ech_accepted(server.get()));

  // An ECH server will fairly naturally record the inner ClientHello random,
  // but an ECH client may forget to update the random once ClientHelloInner is
  // selected.
  uint8_t client_random1[SSL3_RANDOM_SIZE];
  uint8_t client_random2[SSL3_RANDOM_SIZE];
  ASSERT_EQ(sizeof(client_random1),
            SSL_get_client_random(client.get(), client_random1,
                                  sizeof(client_random1)));
  ASSERT_EQ(sizeof(client_random2),
            SSL_get_client_random(server.get(), client_random2,
                                  sizeof(client_random2)));
  EXPECT_EQ(Bytes(client_random1), Bytes(client_random2));
}

// GetECHLength sets |*out_client_hello_len| and |*out_ech_len| to the lengths
// of the ClientHello and ECH extension, respectively, when a client created
// from |ctx| constructs a ClientHello with name |name| and an ECHConfig with
// maximum name length |max_name_len|.
static bool GetECHLength(SSL_CTX *ctx, size_t *out_client_hello_len,
                         size_t *out_ech_len, size_t max_name_len,
                         const char *name) {
  bssl::ScopedEVP_HPKE_KEY key;
  uint8_t *ech_config;
  size_t ech_config_len;
  if (!EVP_HPKE_KEY_generate(key.get(), EVP_hpke_x25519_hkdf_sha256()) ||
      !SSL_marshal_ech_config(&ech_config, &ech_config_len,
                              /*config_id=*/1, key.get(), "public.example",
                              max_name_len)) {
    return false;
  }
  bssl::UniquePtr<uint8_t> free_ech_config(ech_config);

  bssl::UniquePtr<SSL_ECH_KEYS> keys(SSL_ECH_KEYS_new());
  if (!keys || !SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1, ech_config,
                                 ech_config_len, key.get())) {
    return false;
  }

  bssl::UniquePtr<SSL> ssl(SSL_new(ctx));
  if (!ssl || !InstallECHConfigList(ssl.get(), keys.get()) ||
      (name != nullptr && !SSL_set_tlsext_host_name(ssl.get(), name))) {
    return false;
  }
  SSL_set_connect_state(ssl.get());

  std::vector<uint8_t> client_hello;
  SSL_CLIENT_HELLO parsed;
  const uint8_t *unused;
  if (!GetClientHello(ssl.get(), &client_hello) ||
      !ssl_client_hello_init(
          ssl.get(), &parsed,
          // Skip record and handshake headers. This assumes the ClientHello
          // fits in one record.
          MakeConstSpan(client_hello)
              .subspan(SSL3_RT_HEADER_LENGTH + SSL3_HM_HEADER_LENGTH)) ||
      !SSL_early_callback_ctx_extension_get(
          &parsed, TLSEXT_TYPE_encrypted_client_hello, &unused, out_ech_len)) {
    return false;
  }
  *out_client_hello_len = client_hello.size();
  return true;
}

TEST(SSLTest, ECHPadding) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);

  // Sample lengths with max_name_len = 128 as baseline.
  size_t client_hello_len_baseline, ech_len_baseline;
  ASSERT_TRUE(GetECHLength(ctx.get(), &client_hello_len_baseline,
                           &ech_len_baseline, 128, "example.com"));

  // Check that all name lengths under the server's maximum look the same.
  for (size_t name_len : {1, 2, 32, 64, 127, 128}) {
    SCOPED_TRACE(name_len);
    size_t client_hello_len, ech_len;
    ASSERT_TRUE(GetECHLength(ctx.get(), &client_hello_len, &ech_len, 128,
                             std::string(name_len, 'a').c_str()));
    EXPECT_EQ(client_hello_len, client_hello_len_baseline);
    EXPECT_EQ(ech_len, ech_len_baseline);
  }

  // When sending no SNI, we must still pad as if we are sending one.
  size_t client_hello_len, ech_len;
  ASSERT_TRUE(
      GetECHLength(ctx.get(), &client_hello_len, &ech_len, 128, nullptr));
  EXPECT_EQ(client_hello_len, client_hello_len_baseline);
  EXPECT_EQ(ech_len, ech_len_baseline);

  // Name lengths above the maximum do not get named-based padding, but the
  // overall input is padded to a multiple of 32.
  size_t client_hello_len_baseline2, ech_len_baseline2;
  ASSERT_TRUE(GetECHLength(ctx.get(), &client_hello_len_baseline2,
                           &ech_len_baseline2, 128,
                           std::string(128 + 32, 'a').c_str()));
  EXPECT_EQ(ech_len_baseline2, ech_len_baseline + 32);
  // The ClientHello lengths may match if we are still under the threshold for
  // padding extension.
  EXPECT_GE(client_hello_len_baseline2, client_hello_len_baseline);

  for (size_t name_len = 128 + 1; name_len < 128 + 32; name_len++) {
    SCOPED_TRACE(name_len);
    ASSERT_TRUE(GetECHLength(ctx.get(), &client_hello_len, &ech_len, 128,
                             std::string(name_len, 'a').c_str()));
    EXPECT_TRUE(ech_len == ech_len_baseline || ech_len == ech_len_baseline2)
        << ech_len;
    EXPECT_TRUE(client_hello_len == client_hello_len_baseline ||
                client_hello_len == client_hello_len_baseline2)
        << client_hello_len;
  }
}

TEST(SSLTest, ECHPublicName) {
  auto str_to_span = [](const char *str) -> Span<const uint8_t> {
    return MakeConstSpan(reinterpret_cast<const uint8_t *>(str), strlen(str));
  };

  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("")));
  EXPECT_TRUE(ssl_is_valid_ech_public_name(str_to_span("example.com")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span(".example.com")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("example.com.")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("example..com")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("www.-example.com")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("www.example-.com")));
  EXPECT_FALSE(
      ssl_is_valid_ech_public_name(str_to_span("no_underscores.example")));
  EXPECT_FALSE(
      ssl_is_valid_ech_public_name(str_to_span("invalid_chars.\x01.example")));
  EXPECT_FALSE(
      ssl_is_valid_ech_public_name(str_to_span("invalid_chars.\xff.example")));
  static const uint8_t kWithNUL[] = {'t', 'e', 's', 't', 0};
  EXPECT_FALSE(ssl_is_valid_ech_public_name(kWithNUL));

  // Test an LDH label with every character and the maximum length.
  EXPECT_TRUE(ssl_is_valid_ech_public_name(str_to_span(
      "abcdefhijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span(
      "abcdefhijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-01234567899")));

  // Inputs with trailing numeric components are rejected.
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("127.0.0.1")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("example.1")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("example.01")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("example.0x01")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("example.0X01")));
  // Leading zeros and values that overflow |uint32_t| are still rejected.
  EXPECT_FALSE(ssl_is_valid_ech_public_name(
      str_to_span("example.123456789000000000000000")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(
      str_to_span("example.012345678900000000000000")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(
      str_to_span("example.0x123456789abcdefABCDEF0")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(
      str_to_span("example.0x0123456789abcdefABCDEF")));
  // Adding a non-digit or non-hex character makes it a valid DNS name again.
  // Single-component numbers are rejected.
  EXPECT_TRUE(ssl_is_valid_ech_public_name(str_to_span("example.1234567890a")));
  EXPECT_TRUE(
      ssl_is_valid_ech_public_name(str_to_span("example.01234567890a")));
  EXPECT_TRUE(
      ssl_is_valid_ech_public_name(str_to_span("example.0x123456789abcdefg")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("1")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("01")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("0x01")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("0X01")));
  // Numbers with trailing dots are rejected. (They are already rejected by the
  // LDH label rules, but the WHATWG URL parser additionally rejects them.)
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("1.")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("01.")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("0x01.")));
  EXPECT_FALSE(ssl_is_valid_ech_public_name(str_to_span("0X01.")));
}

// These test certificates generated with the following Go program.
  /* clang-format off
func main() {
  notBefore := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
  notAfter := time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC)
  rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  rootTemplate := &x509.Certificate{
    SerialNumber:          big.NewInt(1),
    Subject:               pkix.Name{CommonName: "Test CA"},
    NotBefore:             notBefore,
    NotAfter:              notAfter,
    BasicConstraintsValid: true,
    IsCA:                  true,
  }
  rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
  root, _ := x509.ParseCertificate(rootDER)
  pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
  leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  leafKeyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
  pem.Encode(os.Stdout, &pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER})
  for i, name := range []string{"public.example", "secret.example"} {
    leafTemplate := &x509.Certificate{
      SerialNumber:          big.NewInt(int64(i) + 2),
      Subject:               pkix.Name{CommonName: name},
      NotBefore:             notBefore,
      NotAfter:              notAfter,
      BasicConstraintsValid: true,
      DNSNames:              []string{name},
    }
    leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
    pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
  }
}
clang-format on */
static bssl::UniquePtr<X509> GetLeafRoot() {
  bssl::UniquePtr<X509> root = CertFromPEM(R"(
-----BEGIN CERTIFICATE-----
MIIBRzCB7aADAgECAgEBMAoGCCqGSM49BAMCMBIxEDAOBgNVBAMTB1Rlc3QgQ0Ew
IBcNMDAwMTAxMDAwMDAwWhgPMjA5OTAxMDEwMDAwMDBaMBIxEDAOBgNVBAMTB1Rl
c3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT5JUjrI1DAxSpEl88UkmJw
tAJqxo/YrSFo9V3MkcNkfTixi5p6MUtO8DazhEgekBcd2+tBAWtl7dy0qpvTqx92
ozIwMDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTw6ftkexAI6o4r5FntJIfL
GU5F4zAKBggqhkjOPQQDAgNJADBGAiEAiiNowddQeHZaZFIygwe6RW5/WG4sUXWC
dkyl9CQzRaYCIQCFS1EvwZbZtMny27fYm1eeYciY0TkJTEi34H1KwyzzIA==
-----END CERTIFICATE-----
)");
  EXPECT_TRUE(root);
  return root;
}

static bssl::UniquePtr<EVP_PKEY> GetLeafKey() {
  bssl::UniquePtr<EVP_PKEY> leaf_key = KeyFromPEM(R"(
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgj5WKHwHnziiyPauf
7QukxTwtTyGZkk8qNdms4puJfxqhRANCAARNrkhxabALDlJrHtvkuDwvCWUF/oVC
hr6PDITHi1lDlJzvVT4aXBH87sH2n2UV5zpx13NHkq1bIC8eRT8eOIe0
-----END PRIVATE KEY-----
)");
  EXPECT_TRUE(leaf_key);
  return leaf_key;
}

static bssl::UniquePtr<X509> GetLeafPublic() {
  bssl::UniquePtr<X509> leaf_public = CertFromPEM(R"(
-----BEGIN CERTIFICATE-----
MIIBaDCCAQ6gAwIBAgIBAjAKBggqhkjOPQQDAjASMRAwDgYDVQQDEwdUZXN0IENB
MCAXDTAwMDEwMTAwMDAwMFoYDzIwOTkwMTAxMDAwMDAwWjAZMRcwFQYDVQQDEw5w
dWJsaWMuZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE2uSHFpsAsO
Umse2+S4PC8JZQX+hUKGvo8MhMeLWUOUnO9VPhpcEfzuwfafZRXnOnHXc0eSrVsg
Lx5FPx44h7SjTDBKMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU8On7ZHsQCOqO
K+RZ7SSHyxlOReMwGQYDVR0RBBIwEIIOcHVibGljLmV4YW1wbGUwCgYIKoZIzj0E
AwIDSAAwRQIhANqZRhDR/+QL05hsWXMYEwaiHifd9iakKoFEhKFchcF3AiBRAeXw
wRGGT6+iPmTYM6N5/IDyAb5B9Ke38O6lLEsUwA==
-----END CERTIFICATE-----
)");
  EXPECT_TRUE(leaf_public);
  return leaf_public;
}

static bssl::UniquePtr<X509> GetLeafSecret() {
  bssl::UniquePtr<X509> leaf_secret = CertFromPEM(R"(
-----BEGIN CERTIFICATE-----
MIIBaTCCAQ6gAwIBAgIBAzAKBggqhkjOPQQDAjASMRAwDgYDVQQDEwdUZXN0IENB
MCAXDTAwMDEwMTAwMDAwMFoYDzIwOTkwMTAxMDAwMDAwWjAZMRcwFQYDVQQDEw5z
ZWNyZXQuZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE2uSHFpsAsO
Umse2+S4PC8JZQX+hUKGvo8MhMeLWUOUnO9VPhpcEfzuwfafZRXnOnHXc0eSrVsg
Lx5FPx44h7SjTDBKMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU8On7ZHsQCOqO
K+RZ7SSHyxlOReMwGQYDVR0RBBIwEIIOc2VjcmV0LmV4YW1wbGUwCgYIKoZIzj0E
AwIDSQAwRgIhAPQdIz1xCFkc9WuSkxOxJDpywZiEp9SnKcxJ9nwrlRp3AiEA+O3+
XRqE7XFhHL+7TNC2a9OOAjQsEF137YPWo+rhgko=
-----END CERTIFICATE-----
)");
  EXPECT_TRUE(leaf_secret);
  return leaf_secret;
}

// When using the built-in verifier, test that |SSL_get0_ech_name_override| is
// applied automatically.
TEST(SSLTest, ECHBuiltinVerifier) {
  // Use different config IDs so that fuzzer mode, which breaks trial
  // decryption, will observe the key mismatch.
  bssl::UniquePtr<SSL_ECH_KEYS> keys = MakeTestECHKeys(/*config_id=*/1);
  ASSERT_TRUE(keys);
  bssl::UniquePtr<SSL_ECH_KEYS> wrong_keys = MakeTestECHKeys(/*config_id=*/2);
  ASSERT_TRUE(wrong_keys);
  bssl::UniquePtr<SSL_CTX> server_ctx =
      CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(server_ctx);
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(client_ctx);

  // Configure the client to verify certificates and expect the secret name.
  // This is the name the client is trying to connect to. If ECH is rejected,
  // BoringSSL will internally override this setting with the public name.
  bssl::UniquePtr<X509_STORE> store(X509_STORE_new());
  ASSERT_TRUE(store);
  ASSERT_TRUE(X509_STORE_add_cert(store.get(), GetLeafRoot().get()));
  SSL_CTX_set_cert_store(client_ctx.get(), store.release());
  SSL_CTX_set_verify(client_ctx.get(), SSL_VERIFY_PEER, nullptr);
  X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(client_ctx.get()),
                              X509_V_FLAG_NO_CHECK_TIME);
  static const char kSecretName[] = "secret.example";
  ASSERT_TRUE(X509_VERIFY_PARAM_set1_host(SSL_CTX_get0_param(client_ctx.get()),
                                          kSecretName, strlen(kSecretName)));

  // For simplicity, we only run through a pair of representative scenarios here
  // and rely on runner.go to verify that |SSL_get0_ech_name_override| behaves
  // correctly.
  for (bool accept_ech : {false, true}) {
    SCOPED_TRACE(accept_ech);
    for (bool use_leaf_secret : {false, true}) {
      SCOPED_TRACE(use_leaf_secret);

      // The server will reject ECH when configured with the wrong keys.
      ASSERT_TRUE(SSL_CTX_set1_ech_keys(
          server_ctx.get(), accept_ech ? keys.get() : wrong_keys.get()));

      bssl::UniquePtr<SSL> client, server;
      ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(),
                                        server_ctx.get()));
      ASSERT_TRUE(InstallECHConfigList(client.get(), keys.get()));

      // Configure the server with the selected certificate.
      ASSERT_TRUE(SSL_use_certificate(
          server.get(),
          use_leaf_secret ? GetLeafSecret().get() : GetLeafPublic().get()));
      ASSERT_TRUE(SSL_use_PrivateKey(server.get(), GetLeafKey().get()));

      // The handshake may fail due to name mismatch or ECH reject. We check
      // |SSL_get_verify_result| to confirm the handshake got far enough.
      CompleteHandshakes(client.get(), server.get());
      EXPECT_EQ(accept_ech == use_leaf_secret ? X509_V_OK
                                              : X509_V_ERR_HOSTNAME_MISMATCH,
                SSL_get_verify_result(client.get()));
    }
  }
}

#if defined(OPENSSL_THREADS)
// Test that the server ECH config can be swapped out while the |SSL_CTX| is
// in use on other threads. This test is intended to be run with TSan.
TEST(SSLTest, ECHThreads) {
  // Generate a pair of ECHConfigs.
  bssl::ScopedEVP_HPKE_KEY key1;
  ASSERT_TRUE(EVP_HPKE_KEY_generate(key1.get(), EVP_hpke_x25519_hkdf_sha256()));
  uint8_t *ech_config1;
  size_t ech_config1_len;
  ASSERT_TRUE(SSL_marshal_ech_config(&ech_config1, &ech_config1_len,
                                     /*config_id=*/1, key1.get(),
                                     "public.example", 16));
  bssl::UniquePtr<uint8_t> free_ech_config1(ech_config1);
  bssl::ScopedEVP_HPKE_KEY key2;
  ASSERT_TRUE(EVP_HPKE_KEY_generate(key2.get(), EVP_hpke_x25519_hkdf_sha256()));
  uint8_t *ech_config2;
  size_t ech_config2_len;
  ASSERT_TRUE(SSL_marshal_ech_config(&ech_config2, &ech_config2_len,
                                     /*config_id=*/2, key2.get(),
                                     "public.example", 16));
  bssl::UniquePtr<uint8_t> free_ech_config2(ech_config2);

  // |keys1| contains the first config. |keys12| contains both.
  bssl::UniquePtr<SSL_ECH_KEYS> keys1(SSL_ECH_KEYS_new());
  ASSERT_TRUE(keys1);
  ASSERT_TRUE(SSL_ECH_KEYS_add(keys1.get(), /*is_retry_config=*/1, ech_config1,
                               ech_config1_len, key1.get()));
  bssl::UniquePtr<SSL_ECH_KEYS> keys12(SSL_ECH_KEYS_new());
  ASSERT_TRUE(keys12);
  ASSERT_TRUE(SSL_ECH_KEYS_add(keys12.get(), /*is_retry_config=*/1, ech_config2,
                               ech_config2_len, key2.get()));
  ASSERT_TRUE(SSL_ECH_KEYS_add(keys12.get(), /*is_retry_config=*/0, ech_config1,
                               ech_config1_len, key1.get()));

  bssl::UniquePtr<SSL_CTX> server_ctx =
      CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(server_ctx);
  ASSERT_TRUE(SSL_CTX_set1_ech_keys(server_ctx.get(), keys1.get()));

  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(client_ctx);
  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(),
                                    server_ctx.get()));
  ASSERT_TRUE(InstallECHConfigList(client.get(), keys1.get()));

  // In parallel, complete the connection and reconfigure the ECHConfig. Note
  // |keys12| supports all the keys in |keys1|, so the handshake should complete
  // the same whichever the server uses.
  std::vector<std::thread> threads;
  threads.emplace_back([&] {
    ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));
    EXPECT_TRUE(SSL_ech_accepted(client.get()));
    EXPECT_TRUE(SSL_ech_accepted(server.get()));
  });
  threads.emplace_back([&] {
    EXPECT_TRUE(SSL_CTX_set1_ech_keys(server_ctx.get(), keys12.get()));
  });
  for (auto &thread : threads) {
    thread.join();
  }
}
#endif  // OPENSSL_THREADS

TEST(SSLTest, TLS13ExporterAvailability) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
      CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  // Configure only TLS 1.3.
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(),
                                    server_ctx.get()));

  std::vector<uint8_t> buffer(32);
  const char *label = "EXPORTER-test-label";

  // The exporters are not available before the handshake starts.
  EXPECT_FALSE(SSL_export_keying_material(client.get(), buffer.data(),
                                          buffer.size(), label, strlen(label),
                                          nullptr, 0, 0));
  EXPECT_FALSE(SSL_export_keying_material(server.get(), buffer.data(),
                                          buffer.size(), label, strlen(label),
                                          nullptr, 0, 0));

  // Send the client's first flight of handshake messages.
  int client_ret = SSL_do_handshake(client.get());
  EXPECT_EQ(SSL_get_error(client.get(), client_ret), SSL_ERROR_WANT_READ);

  // The handshake isn't far enough for the exporters to work.
  EXPECT_FALSE(SSL_export_keying_material(client.get(), buffer.data(),
                                          buffer.size(), label, strlen(label),
                                          nullptr, 0, 0));
  EXPECT_FALSE(SSL_export_keying_material(server.get(), buffer.data(),
                                          buffer.size(), label, strlen(label),
                                          nullptr, 0, 0));

  // Send all the server's handshake messages.
  int server_ret = SSL_do_handshake(server.get());
  EXPECT_EQ(SSL_get_error(server.get(), server_ret), SSL_ERROR_WANT_READ);

  // At this point in the handshake, the server should have the exporter key
  // derived since it's sent its Finished message. The client hasn't yet
  // processed the server's handshake messages, so the exporter shouldn't be
  // available to the client.
  EXPECT_FALSE(SSL_export_keying_material(client.get(), buffer.data(),
                                          buffer.size(), label, strlen(label),
                                          nullptr, 0, 0));
  EXPECT_TRUE(SSL_export_keying_material(server.get(), buffer.data(),
                                         buffer.size(), label, strlen(label),
                                         nullptr, 0, 0));

  // Finish the handshake on the client.
  EXPECT_EQ(SSL_do_handshake(client.get()), 1);

  // The exporter should be available on both endpoints.
  EXPECT_TRUE(SSL_export_keying_material(client.get(), buffer.data(),
                                         buffer.size(), label, strlen(label),
                                         nullptr, 0, 0));
  EXPECT_TRUE(SSL_export_keying_material(server.get(), buffer.data(),
                                         buffer.size(), label, strlen(label),
                                         nullptr, 0, 0));

  // Finish the handshake on the server.
  EXPECT_EQ(SSL_do_handshake(server.get()), 1);

  // The exporter should still be available on both endpoints.
  EXPECT_TRUE(SSL_export_keying_material(client.get(), buffer.data(),
                                         buffer.size(), label, strlen(label),
                                         nullptr, 0, 0));
  EXPECT_TRUE(SSL_export_keying_material(server.get(), buffer.data(),
                                         buffer.size(), label, strlen(label),
                                         nullptr, 0, 0));
}

static void AppendSession(SSL_SESSION *session, void *arg) {
  std::vector<SSL_SESSION *> *out =
      reinterpret_cast<std::vector<SSL_SESSION *> *>(arg);
  out->push_back(session);
}

// CacheEquals returns true if |ctx|'s session cache consists of |expected|, in
// order.
static bool CacheEquals(SSL_CTX *ctx,
                        const std::vector<SSL_SESSION *> &expected) {
  // Check the linked list.
  SSL_SESSION *ptr = ctx->session_cache_head;
  for (SSL_SESSION *session : expected) {
    if (ptr != session) {
      return false;
    }
    // Redundant w/ above, but avoids static analysis failure
    if (ptr == nullptr) {
      return false;
    }
    // TODO(davidben): This is an absurd way to denote the end of the list.
    if (ptr->next ==
        reinterpret_cast<SSL_SESSION *>(&ctx->session_cache_tail)) {
      ptr = nullptr;
    } else {
      ptr = ptr->next;
    }
  }
  if (ptr != nullptr) {
    return false;
  }

  // Check the hash table.
  std::vector<SSL_SESSION *> actual, expected_copy;
  lh_SSL_SESSION_doall_arg(ctx->sessions, AppendSession, &actual);
  expected_copy = expected;

  std::sort(actual.begin(), actual.end());
  std::sort(expected_copy.begin(), expected_copy.end());

  return actual == expected_copy;
}

static bssl::UniquePtr<SSL_SESSION> CreateTestSession(uint32_t number) {
  bssl::UniquePtr<SSL_CTX> ssl_ctx(SSL_CTX_new(TLS_method()));
  if (!ssl_ctx) {
    return nullptr;
  }
  bssl::UniquePtr<SSL_SESSION> ret(SSL_SESSION_new(ssl_ctx.get()));
  if (!ret) {
    return nullptr;
  }

  uint8_t id[SSL3_SSL_SESSION_ID_LENGTH] = {0};
  OPENSSL_memcpy(id, &number, sizeof(number));
  if (!SSL_SESSION_set1_id(ret.get(), id, sizeof(id))) {
    return nullptr;
  }
  return ret;
}

// Test that the internal session cache behaves as expected.
TEST(SSLTest, InternalSessionCache) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);

  // Prepare 10 test sessions.
  std::vector<bssl::UniquePtr<SSL_SESSION>> sessions;
  for (int i = 0; i < 10; i++) {
    bssl::UniquePtr<SSL_SESSION> session = CreateTestSession(i);
    ASSERT_TRUE(session);
    sessions.push_back(std::move(session));
  }

  SSL_CTX_sess_set_cache_size(ctx.get(), 5);

  // Insert all the test sessions.
  for (const auto &session : sessions) {
    ASSERT_TRUE(SSL_CTX_add_session(ctx.get(), session.get()));
  }

  // Only the last five should be in the list.
  ASSERT_TRUE(CacheEquals(
      ctx.get(), {sessions[9].get(), sessions[8].get(), sessions[7].get(),
                  sessions[6].get(), sessions[5].get()}));

  // Inserting an element already in the cache should fail and leave the cache
  // unchanged.
  ASSERT_FALSE(SSL_CTX_add_session(ctx.get(), sessions[7].get()));
  ASSERT_TRUE(CacheEquals(
      ctx.get(), {sessions[9].get(), sessions[8].get(), sessions[7].get(),
                  sessions[6].get(), sessions[5].get()}));

  // Although collisions should be impossible (256-bit session IDs), the cache
  // must handle them gracefully.
  bssl::UniquePtr<SSL_SESSION> collision(CreateTestSession(7));
  ASSERT_TRUE(collision);
  ASSERT_TRUE(SSL_CTX_add_session(ctx.get(), collision.get()));
  ASSERT_TRUE(CacheEquals(
      ctx.get(), {collision.get(), sessions[9].get(), sessions[8].get(),
                  sessions[6].get(), sessions[5].get()}));

  // Removing sessions behaves correctly.
  ASSERT_TRUE(SSL_CTX_remove_session(ctx.get(), sessions[6].get()));
  ASSERT_TRUE(CacheEquals(ctx.get(), {collision.get(), sessions[9].get(),
                                      sessions[8].get(), sessions[5].get()}));

  // Removing sessions requires an exact match.
  ASSERT_FALSE(SSL_CTX_remove_session(ctx.get(), sessions[0].get()));
  ASSERT_FALSE(SSL_CTX_remove_session(ctx.get(), sessions[7].get()));

  // The cache remains unchanged.
  ASSERT_TRUE(CacheEquals(ctx.get(), {collision.get(), sessions[9].get(),
                                      sessions[8].get(), sessions[5].get()}));
}

static uint16_t EpochFromSequence(uint64_t seq) {
  return static_cast<uint16_t>(seq >> 48);
}

static const uint8_t kTestName[] = {
    0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
    0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
    0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65,
    0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49,
    0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67,
    0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64,
};

// SSLVersionTest executes its test cases under all available protocol versions.
// Test cases call |Connect| to create a connection using context objects with
// the protocol version fixed to the current version under test.
class SSLVersionTest : public ::testing::TestWithParam<::std::tuple<VersionParam, int>> {
 protected:
  SSLVersionTest() : cert_(GetTestCertificate()), key_(GetTestKey()) {}

  void SetUp() { ResetContexts(); }

  bssl::UniquePtr<SSL_CTX> CreateContext() const {
    const SSL_METHOD *method = is_dtls() ? DTLS_method() : TLS_method();
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(method));
    if (!ctx || !SSL_CTX_set_min_proto_version(ctx.get(), version()) ||
        !SSL_CTX_set_max_proto_version(ctx.get(), version())) {
      return nullptr;
    }

    if (enable_read_ahead()) {
      SSL_CTX_set_read_ahead(ctx.get(), 1);
      SSL_CTX_set_default_read_buffer_len(ctx.get(), read_ahead_buffer_size());
    }
    return ctx;
  }

  void ResetContexts() {
    ASSERT_TRUE(cert_);
    ASSERT_TRUE(key_);
    client_ctx_ = CreateContext();
    ASSERT_TRUE(client_ctx_);
    server_ctx_ = CreateContext();
    ASSERT_TRUE(server_ctx_);
    // Set up a server cert. Client certs can be set up explicitly.
    ASSERT_TRUE(UseCertAndKey(server_ctx_.get()));
  }

  bool UseCertAndKey(SSL_CTX *ctx) const {
    return SSL_CTX_use_certificate(ctx, cert_.get()) &&
           SSL_CTX_use_PrivateKey(ctx, key_.get());
  }

  bool Connect(const ClientConfig &config = ClientConfig()) {
    bool connected = ConnectClientAndServer(
        &client_, &server_, client_ctx_.get(), server_ctx_.get(), config,
        shed_handshake_config_);
    if (connected) {
      TransferServerSSL();
    }
    return connected;
  }

  VersionParam getVersionParam() const {
    return std::get<0>(GetParam());
  }

  void TransferServerSSL() {
    if (!getVersionParam().transfer_ssl) {
      return;
    }
    // |server_| is reset to hold the transferred SSL.
    TransferSSL(&server_, server_ctx_.get(), nullptr);
  }

  uint16_t version() const { return getVersionParam().version; }

  bool is_dtls() const {
    return getVersionParam().ssl_method == VersionParam::is_dtls;
  }

  size_t read_ahead_buffer_size() const {
    return std::get<1>(GetParam());
  }

  bool enable_read_ahead() const {
    return read_ahead_buffer_size() != 0;
  }

  void CheckCounterInit() {
    EXPECT_EQ(SSL_CTX_sess_connect(client_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_connect(server_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_connect_good(client_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_connect_good(server_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_connect_renegotiate(client_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_connect_renegotiate(server_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_accept(client_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_accept(server_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_accept_renegotiate(client_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_accept_renegotiate(server_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_accept_good(client_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_accept_good(server_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_hits(client_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_hits(server_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_cb_hits(client_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_cb_hits(server_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_misses(client_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_misses(server_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_timeouts(client_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_timeouts(server_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_cache_full(client_ctx_.get()), 0);
    EXPECT_EQ(SSL_CTX_sess_cache_full(server_ctx_.get()), 0);
  }

  bool shed_handshake_config_ = true;
  bssl::UniquePtr<SSL> client_, server_;
  bssl::UniquePtr<SSL_CTX> server_ctx_, client_ctx_;
  bssl::UniquePtr<X509> cert_;
  bssl::UniquePtr<EVP_PKEY> key_;
};

INSTANTIATE_TEST_SUITE_P(WithVersion, SSLVersionTest,
                          testing::Combine(::testing::ValuesIn(kAllVersions), testing::Values(0, 128, 512, 8192, 65535)),
                          [](const testing::TestParamInfo<::std::tuple<VersionParam, int>>& test_info) {
                            std::string test_name = std::string(std::get<0>(test_info.param).name) + "_BufferSize_";
                            return test_name + std::to_string(std::get<1>(test_info.param));
                          });

TEST_P(SSLVersionTest, SequenceNumber) {
  CheckCounterInit();
  ASSERT_TRUE(Connect());
  // Counters should count one two-way successful connection.
  EXPECT_EQ(SSL_CTX_sess_connect(client_ctx_.get()), 1);
  EXPECT_EQ(SSL_CTX_sess_connect_good(client_ctx_.get()), 1);
  EXPECT_EQ(SSL_CTX_sess_accept(server_ctx_.get()), 1);
  EXPECT_EQ(SSL_CTX_sess_accept_good(server_ctx_.get()), 1);

  // Drain any post-handshake messages to ensure there are no unread records
  // on either end.
  ASSERT_TRUE(FlushNewSessionTickets(client_.get(), server_.get()));

  uint64_t client_read_seq = SSL_get_read_sequence(client_.get());
  uint64_t client_write_seq = SSL_get_write_sequence(client_.get());
  uint64_t server_read_seq = SSL_get_read_sequence(server_.get());
  uint64_t server_write_seq = SSL_get_write_sequence(server_.get());

  if (is_dtls()) {
    // Both client and server must be at epoch 1.
    EXPECT_EQ(EpochFromSequence(client_read_seq), 1);
    EXPECT_EQ(EpochFromSequence(client_write_seq), 1);
    EXPECT_EQ(EpochFromSequence(server_read_seq), 1);
    EXPECT_EQ(EpochFromSequence(server_write_seq), 1);

    // The next record to be written should exceed the largest received.
    EXPECT_GT(client_write_seq, server_read_seq);
    EXPECT_GT(server_write_seq, client_read_seq);
  } else {
    // The next record to be written should equal the next to be received.
    EXPECT_EQ(client_write_seq, server_read_seq);
    EXPECT_EQ(server_write_seq, client_read_seq);
  }

  // Send a record from client to server.
  uint8_t byte = 0;
  EXPECT_EQ(SSL_write(client_.get(), &byte, 1), 1);
  EXPECT_EQ(SSL_read(server_.get(), &byte, 1), 1);

  // The client write and server read sequence numbers should have
  // incremented.
  EXPECT_EQ(client_write_seq + 1, SSL_get_write_sequence(client_.get()));
  EXPECT_EQ(server_read_seq + 1, SSL_get_read_sequence(server_.get()));
}

TEST_P(SSLVersionTest, OneSidedShutdown) {
  // SSL_shutdown is a no-op in DTLS.
  if (is_dtls()) {
    return;
  }
  ASSERT_TRUE(Connect());

  // Shut down half the connection. |SSL_shutdown| will return 0 to signal only
  // one side has shut down.
  ASSERT_EQ(SSL_shutdown(client_.get()), 0);

  // Reading from the server should consume the EOF.
  uint8_t byte;
  ASSERT_EQ(SSL_read(server_.get(), &byte, 1), 0);
  ASSERT_EQ(SSL_get_error(server_.get(), 0), SSL_ERROR_ZERO_RETURN);

  // However, the server may continue to write data and then shut down the
  // connection.
  byte = 42;
  ASSERT_EQ(SSL_write(server_.get(), &byte, 1), 1);
  ASSERT_EQ(SSL_read(client_.get(), &byte, 1), 1);
  ASSERT_EQ(byte, 42);

  // The server may then shutdown the connection.
  EXPECT_EQ(SSL_shutdown(server_.get()), 1);
  EXPECT_EQ(SSL_shutdown(client_.get()), 1);
}

// Test that, after calling |SSL_shutdown|, |SSL_write| fails.
TEST_P(SSLVersionTest, WriteAfterShutdown) {
  ASSERT_TRUE(Connect());

  for (SSL *ssl : {client_.get(), server_.get()}) {
    SCOPED_TRACE(SSL_is_server(ssl) ? "server" : "client");

    bssl::UniquePtr<BIO> mem(BIO_new(BIO_s_mem()));
    ASSERT_TRUE(mem);
    SSL_set0_wbio(ssl, bssl::UpRef(mem).release());

    // Shut down half the connection. |SSL_shutdown| will return 0 to signal
    // only one side has shut down.
    ASSERT_EQ(SSL_shutdown(ssl), 0);

    // |ssl| should have written an alert to the transport.
    const uint8_t *unused;
    size_t len;
    ASSERT_TRUE(BIO_mem_contents(mem.get(), &unused, &len));
    EXPECT_NE(0u, len);
    EXPECT_TRUE(BIO_reset(mem.get()));

    // Writing should fail.
    EXPECT_EQ(-1, SSL_write(ssl, "a", 1));

    // Nothing should be written to the transport.
    ASSERT_TRUE(BIO_mem_contents(mem.get(), &unused, &len));
    EXPECT_EQ(0u, len);
  }
}

// Test that, after sending a fatal alert in a failed |SSL_read|, |SSL_write|
// fails.
TEST_P(SSLVersionTest, WriteAfterReadSentFatalAlert) {
  // Decryption failures are not fatal in DTLS.
  if (is_dtls()) {
    return;
  }

  ASSERT_TRUE(Connect());

  // Save the write |BIO|s as the test will overwrite them.
  bssl::UniquePtr<BIO> client_wbio = bssl::UpRef(SSL_get_wbio(client_.get()));
  bssl::UniquePtr<BIO> server_wbio = bssl::UpRef(SSL_get_wbio(server_.get()));

  for (bool test_server : {false, true}) {
    SCOPED_TRACE(test_server ? "server" : "client");
    SSL *ssl = test_server ? server_.get() : client_.get();
    BIO *other_wbio = test_server ? client_wbio.get() : server_wbio.get();

    bssl::UniquePtr<BIO> mem(BIO_new(BIO_s_mem()));
    ASSERT_TRUE(mem);
    SSL_set0_wbio(ssl, bssl::UpRef(mem).release());

    // Read an invalid record from the peer.
    static const uint8_t kInvalidRecord[] = "invalid record";
    EXPECT_EQ(int{sizeof(kInvalidRecord)},
              BIO_write(other_wbio, kInvalidRecord, sizeof(kInvalidRecord)));
    char buf[256];
    EXPECT_EQ(-1, SSL_read(ssl, buf, sizeof(buf)));

    // |ssl| should have written an alert to the transport.
    const uint8_t *unused;
    size_t len;
    ASSERT_TRUE(BIO_mem_contents(mem.get(), &unused, &len));
    EXPECT_NE(0u, len);
    EXPECT_TRUE(BIO_reset(mem.get()));

    // Writing should fail.
    EXPECT_EQ(-1, SSL_write(ssl, "a", 1));

    // Nothing should be written to the transport.
    ASSERT_TRUE(BIO_mem_contents(mem.get(), &unused, &len));
    EXPECT_EQ(0u, len);
  }
}

// Test that, after sending a fatal alert from the handshake, |SSL_write| fails.
TEST_P(SSLVersionTest, WriteAfterHandshakeSentFatalAlert) {
  for (bool test_server : {false, true}) {
    SCOPED_TRACE(test_server ? "server" : "client");

    bssl::UniquePtr<SSL> ssl(
        SSL_new(test_server ? server_ctx_.get() : client_ctx_.get()));
    ASSERT_TRUE(ssl);
    if (test_server) {
      SSL_set_accept_state(ssl.get());
    } else {
      SSL_set_connect_state(ssl.get());
    }

    std::vector<uint8_t> invalid;
    if (is_dtls()) {
      // In DTLS, invalid records are discarded. To cause the handshake to fail,
      // use a valid handshake record with invalid contents.
      invalid.push_back(SSL3_RT_HANDSHAKE);
      invalid.push_back(DTLS1_VERSION >> 8);
      invalid.push_back(DTLS1_VERSION & 0xff);
      // epoch and sequence_number
      for (int i = 0; i < 8; i++) {
        invalid.push_back(0);
      }
      // A one-byte fragment is invalid.
      invalid.push_back(0);
      invalid.push_back(1);
      // Arbitrary contents.
      invalid.push_back(0);
    } else {
      invalid = {'i', 'n', 'v', 'a', 'l', 'i', 'd'};
    }
    bssl::UniquePtr<BIO> rbio(BIO_new_mem_buf(invalid.data(), invalid.size()));
    ASSERT_TRUE(rbio);
    SSL_set0_rbio(ssl.get(), rbio.release());

    bssl::UniquePtr<BIO> mem(BIO_new(BIO_s_mem()));
    ASSERT_TRUE(mem);
    SSL_set0_wbio(ssl.get(), bssl::UpRef(mem).release());

    // The handshake should fail.
    EXPECT_EQ(-1, SSL_do_handshake(ssl.get()));
    EXPECT_EQ(SSL_ERROR_SSL, SSL_get_error(ssl.get(), -1));
    uint32_t err = ERR_get_error();

    // |ssl| should have written an alert (and, in the client's case, a
    // ClientHello) to the transport.
    const uint8_t *unused;
    size_t len;
    ASSERT_TRUE(BIO_mem_contents(mem.get(), &unused, &len));
    EXPECT_NE(0u, len);
    EXPECT_TRUE(BIO_reset(mem.get()));

    // Writing should fail, with the same error as the handshake.
    EXPECT_EQ(-1, SSL_write(ssl.get(), "a", 1));
    EXPECT_EQ(SSL_ERROR_SSL, SSL_get_error(ssl.get(), -1));
    EXPECT_EQ(err, ERR_get_error());

    // Nothing should be written to the transport.
    ASSERT_TRUE(BIO_mem_contents(mem.get(), &unused, &len));
    EXPECT_EQ(0u, len);
  }
}

// Test that, after seeing TLS 1.2 in response to early data, |SSL_write|
// continues to report |SSL_R_WRONG_VERSION_ON_EARLY_DATA|. See
// https://crbug.com/1078515.
TEST(SSLTest, WriteAfterWrongVersionOnEarlyData) {
  // Set up some 0-RTT-enabled contexts.
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
      CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  SSL_CTX_set_early_data_enabled(client_ctx.get(), 1);
  SSL_CTX_set_early_data_enabled(server_ctx.get(), 1);
  SSL_CTX_set_session_cache_mode(client_ctx.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx.get(), SSL_SESS_CACHE_BOTH);

  // Get an early-data-capable session.
  bssl::UniquePtr<SSL_SESSION> session =
      CreateClientSession(client_ctx.get(), server_ctx.get());
  ASSERT_TRUE(session);
  EXPECT_TRUE(SSL_SESSION_early_data_capable(session.get()));

  // Offer the session to the server, but now the server speaks TLS 1.2.
  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(),
                                    server_ctx.get()));
  SSL_set_session(client.get(), session.get());
  EXPECT_TRUE(SSL_set_max_proto_version(server.get(), TLS1_2_VERSION));

  // The client handshake initially succeeds in the early data state.
  EXPECT_EQ(1, SSL_do_handshake(client.get()));
  EXPECT_TRUE(SSL_in_early_data(client.get()));

  // The server processes the ClientHello and negotiates TLS 1.2.
  EXPECT_EQ(-1, SSL_do_handshake(server.get()));
  EXPECT_EQ(SSL_ERROR_WANT_READ, SSL_get_error(server.get(), -1));
  EXPECT_EQ(TLS1_2_VERSION, SSL_version(server.get()));

  // Capture the client's output.
  bssl::UniquePtr<BIO> mem(BIO_new(BIO_s_mem()));
  ASSERT_TRUE(mem);
  SSL_set0_wbio(client.get(), bssl::UpRef(mem).release());

  // The client processes the ServerHello and fails.
  EXPECT_EQ(-1, SSL_do_handshake(client.get()));
  EXPECT_EQ(SSL_ERROR_SSL, SSL_get_error(client.get(), -1));
  EXPECT_TRUE(ErrorEquals(ERR_get_error(), ERR_LIB_SSL,
                          SSL_R_WRONG_VERSION_ON_EARLY_DATA));

  // The client should have written an alert to the transport.
  const uint8_t *unused;
  size_t len;
  ASSERT_TRUE(BIO_mem_contents(mem.get(), &unused, &len));
  EXPECT_NE(0u, len);
  EXPECT_TRUE(BIO_reset(mem.get()));

  // Writing should fail, with the same error as the handshake.
  EXPECT_EQ(-1, SSL_write(client.get(), "a", 1));
  EXPECT_EQ(SSL_ERROR_SSL, SSL_get_error(client.get(), -1));
  EXPECT_TRUE(ErrorEquals(ERR_get_error(), ERR_LIB_SSL,
                          SSL_R_WRONG_VERSION_ON_EARLY_DATA));

  // Nothing should be written to the transport.
  ASSERT_TRUE(BIO_mem_contents(mem.get(), &unused, &len));
  EXPECT_EQ(0u, len);
}

TEST(SSLTest, SessionDuplication) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
      CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));

  SSL_SESSION *session0 = SSL_get_session(client.get());
  bssl::UniquePtr<SSL_SESSION> session1 =
      bssl::SSL_SESSION_dup(session0, SSL_SESSION_DUP_ALL);
  ASSERT_TRUE(session1);

  session1->not_resumable = false;

  uint8_t *s0_bytes, *s1_bytes;
  size_t s0_len, s1_len;

  ASSERT_TRUE(SSL_SESSION_to_bytes(session0, &s0_bytes, &s0_len));
  bssl::UniquePtr<uint8_t> free_s0(s0_bytes);

  ASSERT_TRUE(SSL_SESSION_to_bytes(session1.get(), &s1_bytes, &s1_len));
  bssl::UniquePtr<uint8_t> free_s1(s1_bytes);

  EXPECT_EQ(Bytes(s0_bytes, s0_len), Bytes(s1_bytes, s1_len));
}

static void ExpectFDs(const SSL *ssl, int rfd, int wfd) {
  EXPECT_EQ(rfd, SSL_get_fd(ssl));
  EXPECT_EQ(rfd, SSL_get_rfd(ssl));
  EXPECT_EQ(wfd, SSL_get_wfd(ssl));

  // The wrapper BIOs are always equal when fds are equal, even if set
  // individually.
  if (rfd == wfd) {
    EXPECT_EQ(SSL_get_rbio(ssl), SSL_get_wbio(ssl));
  }
}

TEST(SSLTest, SetFD) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);

  // Test setting different read and write FDs.
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);
  EXPECT_TRUE(SSL_set_rfd(ssl.get(), 1));
  EXPECT_TRUE(SSL_set_wfd(ssl.get(), 2));
  ExpectFDs(ssl.get(), 1, 2);

  // Test setting the same FD.
  ssl.reset(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);
  EXPECT_TRUE(SSL_set_fd(ssl.get(), 1));
  ExpectFDs(ssl.get(), 1, 1);

  // Test setting the same FD one side at a time.
  ssl.reset(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);
  EXPECT_TRUE(SSL_set_rfd(ssl.get(), 1));
  EXPECT_TRUE(SSL_set_wfd(ssl.get(), 1));
  ExpectFDs(ssl.get(), 1, 1);

  // Test setting the same FD in the other order.
  ssl.reset(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);
  EXPECT_TRUE(SSL_set_wfd(ssl.get(), 1));
  EXPECT_TRUE(SSL_set_rfd(ssl.get(), 1));
  ExpectFDs(ssl.get(), 1, 1);

  // Test changing the read FD partway through.
  ssl.reset(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);
  EXPECT_TRUE(SSL_set_fd(ssl.get(), 1));
  EXPECT_TRUE(SSL_set_rfd(ssl.get(), 2));
  ExpectFDs(ssl.get(), 2, 1);

  // Test changing the write FD partway through.
  ssl.reset(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);
  EXPECT_TRUE(SSL_set_fd(ssl.get(), 1));
  EXPECT_TRUE(SSL_set_wfd(ssl.get(), 2));
  ExpectFDs(ssl.get(), 1, 2);

  // Test a no-op change to the read FD partway through.
  ssl.reset(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);
  EXPECT_TRUE(SSL_set_fd(ssl.get(), 1));
  EXPECT_TRUE(SSL_set_rfd(ssl.get(), 1));
  ExpectFDs(ssl.get(), 1, 1);

  // Test a no-op change to the write FD partway through.
  ssl.reset(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);
  EXPECT_TRUE(SSL_set_fd(ssl.get(), 1));
  EXPECT_TRUE(SSL_set_wfd(ssl.get(), 1));
  ExpectFDs(ssl.get(), 1, 1);

  // ASan builds will implicitly test that the internal |BIO| reference-counting
  // is correct.
}

TEST(SSLTest, SetBIO) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);

  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  bssl::UniquePtr<BIO> bio1(BIO_new(BIO_s_mem())), bio2(BIO_new(BIO_s_mem())),
      bio3(BIO_new(BIO_s_mem()));
  ASSERT_TRUE(ssl);
  ASSERT_TRUE(bio1);
  ASSERT_TRUE(bio2);
  ASSERT_TRUE(bio3);

  // SSL_set_bio takes one reference when the parameters are the same.
  BIO_up_ref(bio1.get());
  SSL_set_bio(ssl.get(), bio1.get(), bio1.get());

  // Repeating the call does nothing.
  SSL_set_bio(ssl.get(), bio1.get(), bio1.get());

  // It takes one reference each when the parameters are different.
  BIO_up_ref(bio2.get());
  BIO_up_ref(bio3.get());
  SSL_set_bio(ssl.get(), bio2.get(), bio3.get());

  // Repeating the call does nothing.
  SSL_set_bio(ssl.get(), bio2.get(), bio3.get());

  // It takes one reference when changing only wbio.
  BIO_up_ref(bio1.get());
  SSL_set_bio(ssl.get(), bio2.get(), bio1.get());

  // It takes one reference when changing only rbio and the two are different.
  BIO_up_ref(bio3.get());
  SSL_set_bio(ssl.get(), bio3.get(), bio1.get());

  // If setting wbio to rbio, it takes no additional references.
  SSL_set_bio(ssl.get(), bio3.get(), bio3.get());

  // From there, wbio may be switched to something else.
  BIO_up_ref(bio1.get());
  SSL_set_bio(ssl.get(), bio3.get(), bio1.get());

  // If setting rbio to wbio, it takes no additional references.
  SSL_set_bio(ssl.get(), bio1.get(), bio1.get());

  // From there, rbio may be switched to something else, but, for historical
  // reasons, it takes a reference to both parameters.
  BIO_up_ref(bio1.get());
  BIO_up_ref(bio2.get());
  SSL_set_bio(ssl.get(), bio2.get(), bio1.get());

  // ASAN builds will implicitly test that the internal |BIO| reference-counting
  // is correct.
}

static int VerifySucceed(X509_STORE_CTX *store_ctx, void *arg) { return 1; }

TEST_P(SSLVersionTest, GetPeerCertificate) {
  ASSERT_TRUE(UseCertAndKey(client_ctx_.get()));

  // Configure both client and server to accept any certificate.
  SSL_CTX_set_verify(client_ctx_.get(),
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     nullptr);
  SSL_CTX_set_cert_verify_callback(client_ctx_.get(), VerifySucceed, NULL);
  SSL_CTX_set_verify(server_ctx_.get(),
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     nullptr);
  SSL_CTX_set_cert_verify_callback(server_ctx_.get(), VerifySucceed, NULL);

  ASSERT_TRUE(Connect());

  // Client and server should both see the leaf certificate.
  bssl::UniquePtr<X509> peer(SSL_get_peer_certificate(server_.get()));
  ASSERT_TRUE(peer);
  ASSERT_EQ(X509_cmp(cert_.get(), peer.get()), 0);

  peer.reset(SSL_get_peer_certificate(client_.get()));
  ASSERT_TRUE(peer);
  ASSERT_EQ(X509_cmp(cert_.get(), peer.get()), 0);

  // However, for historical reasons, the X509 chain includes the leaf on the
  // client, but does not on the server.
  EXPECT_EQ(sk_X509_num(SSL_get_peer_cert_chain(client_.get())), 1u);
  EXPECT_EQ(sk_CRYPTO_BUFFER_num(SSL_get0_peer_certificates(client_.get())),
            1u);

  EXPECT_EQ(sk_X509_num(SSL_get_peer_cert_chain(server_.get())), 0u);
  EXPECT_EQ(sk_CRYPTO_BUFFER_num(SSL_get0_peer_certificates(server_.get())),
            1u);
}

TEST_P(SSLVersionTest, NoPeerCertificate) {
  SSL_CTX_set_verify(server_ctx_.get(), SSL_VERIFY_PEER, nullptr);
  SSL_CTX_set_cert_verify_callback(server_ctx_.get(), VerifySucceed, NULL);
  SSL_CTX_set_cert_verify_callback(client_ctx_.get(), VerifySucceed, NULL);

  ASSERT_TRUE(Connect());

  // Server should not see a peer certificate.
  bssl::UniquePtr<X509> peer(SSL_get_peer_certificate(server_.get()));
  ASSERT_FALSE(peer);
  ASSERT_FALSE(SSL_get0_peer_certificates(server_.get()));
}

TEST_P(SSLVersionTest, RetainOnlySHA256OfCerts) {
  uint8_t *cert_der = NULL;
  int cert_der_len = i2d_X509(cert_.get(), &cert_der);
  ASSERT_GE(cert_der_len, 0);
  bssl::UniquePtr<uint8_t> free_cert_der(cert_der);

  uint8_t cert_sha256[SHA256_DIGEST_LENGTH];
  SHA256(cert_der, cert_der_len, cert_sha256);

  ASSERT_TRUE(UseCertAndKey(client_ctx_.get()));

  // Configure both client and server to accept any certificate, but the
  // server must retain only the SHA-256 of the peer.
  SSL_CTX_set_verify(client_ctx_.get(),
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     nullptr);
  SSL_CTX_set_verify(server_ctx_.get(),
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     nullptr);
  SSL_CTX_set_cert_verify_callback(client_ctx_.get(), VerifySucceed, NULL);
  SSL_CTX_set_cert_verify_callback(server_ctx_.get(), VerifySucceed, NULL);
  SSL_CTX_set_retain_only_sha256_of_client_certs(server_ctx_.get(), 1);

  ASSERT_TRUE(Connect());

  // The peer certificate has been dropped.
  bssl::UniquePtr<X509> peer(SSL_get_peer_certificate(server_.get()));
  EXPECT_FALSE(peer);

  SSL_SESSION *session = SSL_get_session(server_.get());
  EXPECT_TRUE(SSL_SESSION_has_peer_sha256(session));

  const uint8_t *peer_sha256;
  size_t peer_sha256_len;
  SSL_SESSION_get0_peer_sha256(session, &peer_sha256, &peer_sha256_len);
  EXPECT_EQ(Bytes(cert_sha256), Bytes(peer_sha256, peer_sha256_len));
}

// Tests that our ClientHellos do not change unexpectedly. These are purely
// change detection tests. If they fail as part of an intentional ClientHello
// change, update the test vector.
TEST(SSLTest, ClientHello) {
  struct {
    uint16_t max_version;
    std::vector<uint8_t> expected;
  } kTests[] = {
    {TLS1_VERSION,
     {0x16, 0x03, 0x01, 0x00, 0x58, 0x01, 0x00, 0x00, 0x54, 0x03, 0x01, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0xc0, 0x09,
      0xc0, 0x13, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x2f, 0x00, 0x35, 0x01, 0x00,
      0x00, 0x1f, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
      0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
      0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00}},
    {TLS1_1_VERSION,
     {0x16, 0x03, 0x01, 0x00, 0x58, 0x01, 0x00, 0x00, 0x54, 0x03, 0x02, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0xc0, 0x09,
      0xc0, 0x13, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x2f, 0x00, 0x35, 0x01, 0x00,
      0x00, 0x1f, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
      0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
      0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00}},
    {TLS1_2_VERSION,
     {0x16, 0x03, 0x01, 0x00, 0x86, 0x01, 0x00, 0x00, 0x82, 0x03, 0x03, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0xcc, 0xa9,
      0xcc, 0xa8, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xc0, 0x09,
      0xc0, 0x13, 0xc0, 0x27, 0xc0, 0x0a, 0xc0, 0x14, 0xc0, 0x28, 0x00, 0x9c,
      0x00, 0x9d, 0x00, 0x2f, 0x00, 0x3c, 0x00, 0x35, 0x01, 0x00, 0x00, 0x37,
      0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00,
      0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x0b, 0x00,
      0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x14, 0x00,
      0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05,
      0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01}},
    {TLS1_3_VERSION,
     {0x16, 0x03, 0x01, 0x00, 0xe9, 0x01, 0x00, 0x00, 0xe5, 0x03, 0x03, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
      0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
      0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x27, 0xc0, 0x0a, 0xc0, 0x14, 0xc0, 0x28,
      0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x3c, 0x00, 0x35, 0x01, 0x00,
      0x00, 0x74, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
      0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
      0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0d, 0x00,
      0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08,
      0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x33, 0x00,
      0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2b, 0x00,
      0x09, 0x08, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01}}
  };

  for (const auto &t : kTests) {
    SCOPED_TRACE(t.max_version);

    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(ctx);
    // Our default cipher list varies by CPU capabilities, so manually place the
    // ChaCha20 ciphers in front.
    const char *cipher_list = "CHACHA20:ALL";
    ASSERT_TRUE(SSL_CTX_set_max_proto_version(ctx.get(), t.max_version));
    ASSERT_TRUE(SSL_CTX_set_strict_cipher_list(ctx.get(), cipher_list));

    // Explicitly set TLS 1.3 ciphersuites so CPU capabilities don't affect order
    ASSERT_TRUE(SSL_CTX_set_ciphersuites(ctx.get(), TLS13_DEFAULT_CIPHER_LIST_AES_HW));

    bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
    ASSERT_TRUE(ssl);
    std::vector<uint8_t> client_hello;
    ASSERT_TRUE(GetClientHello(ssl.get(), &client_hello));

    // Zero the client_random.
    constexpr size_t kRandomOffset = 1 + 2 + 2 +  // record header
                                     1 + 3 +      // handshake message header
                                     2;           // client_version

    int pre = client_hello.size();
    if (t.max_version == TLS1_3_VERSION) {
      ASSERT_GE(client_hello.size(), kRandomOffset + SSL3_RANDOM_SIZE + 1 + SSL3_SESSION_ID_SIZE);
      OPENSSL_memset(client_hello.data() + kRandomOffset, 0, SSL3_RANDOM_SIZE + 1  + SSL3_SESSION_ID_SIZE);
      // Jump to key share extension and zero out the key
      OPENSSL_memset(client_hello.data() + 187, 0, 32);
    } else {
      ASSERT_GE(client_hello.size(), kRandomOffset + SSL3_RANDOM_SIZE);
      OPENSSL_memset(client_hello.data() + kRandomOffset, 0, SSL3_RANDOM_SIZE);
    }
    int post = client_hello.size();
    ASSERT_EQ(pre, post);

    if (client_hello != t.expected) {
      ADD_FAILURE() << "ClientHellos did not match.";
      // Print the value manually so it is easier to update the test vector.
      for (size_t i = 0; i < client_hello.size(); i += 12) {
        printf("     %c", i == 0 ? '{' : ' ');
        for (size_t j = i; j < client_hello.size() && j < i + 12; j++) {
          if (j > i) {
            printf(" ");
          }
          printf("0x%02x", client_hello[j]);
          if (j < client_hello.size() - 1) {
            printf(",");
          }
        }
        if (i + 12 >= client_hello.size()) {
          printf("}},");
        }
        printf("\n");
      }
    }
  }
}

static void ExpectSessionReused(SSL_CTX *client_ctx, SSL_CTX *server_ctx,
                                SSL_SESSION *session, bool want_reused) {
  bssl::UniquePtr<SSL> client, server;
  ClientConfig config;
  config.session = session;
  ASSERT_TRUE(
      ConnectClientAndServer(&client, &server, client_ctx, server_ctx, config));

  EXPECT_EQ(SSL_session_reused(client.get()), SSL_session_reused(server.get()));

  bool was_reused = !!SSL_session_reused(client.get());
  EXPECT_EQ(was_reused, want_reused);
}

static bssl::UniquePtr<SSL_SESSION> ExpectSessionRenewed(SSL_CTX *client_ctx,
                                                         SSL_CTX *server_ctx,
                                                         SSL_SESSION *session) {
  g_last_session = nullptr;
  SSL_CTX_sess_set_new_cb(client_ctx, SaveLastSession);

  bssl::UniquePtr<SSL> client, server;
  ClientConfig config;
  config.session = session;
  if (!ConnectClientAndServer(&client, &server, client_ctx, server_ctx,
                              config) ||
      !FlushNewSessionTickets(client.get(), server.get())) {
    fprintf(stderr, "Failed to connect client and server.\n");
    return nullptr;
  }

  if (SSL_session_reused(client.get()) != SSL_session_reused(server.get())) {
    fprintf(stderr, "Client and server were inconsistent.\n");
    return nullptr;
  }

  if (!SSL_session_reused(client.get())) {
    fprintf(stderr, "Session was not reused.\n");
    return nullptr;
  }

  SSL_CTX_sess_set_new_cb(client_ctx, nullptr);

  if (!g_last_session) {
    fprintf(stderr, "Client did not receive a renewed session.\n");
    return nullptr;
  }
  return std::move(g_last_session);
}

static void ExpectTicketKeyChanged(SSL_CTX *ctx, uint8_t *inout_key,
                                   bool changed) {
  uint8_t new_key[kTicketKeyLen];
  // May return 0, 1 or 48.
  ASSERT_EQ(SSL_CTX_get_tlsext_ticket_keys(ctx, new_key, kTicketKeyLen), 1);
  if (changed) {
    ASSERT_NE(Bytes(inout_key, kTicketKeyLen), Bytes(new_key));
  } else {
    ASSERT_EQ(Bytes(inout_key, kTicketKeyLen), Bytes(new_key));
  }
  OPENSSL_memcpy(inout_key, new_key, kTicketKeyLen);
}

static int SwitchSessionIDContextSNI(SSL *ssl, int *out_alert, void *arg) {
  static const uint8_t kContext[] = {3};

  if (!SSL_set_session_id_context(ssl, kContext, sizeof(kContext))) {
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }

  return SSL_TLSEXT_ERR_OK;
}

TEST_P(SSLVersionTest, SessionIDContext) {
  static const uint8_t kContext1[] = {1};
  static const uint8_t kContext2[] = {2};

  ASSERT_TRUE(SSL_CTX_set_session_id_context(server_ctx_.get(), kContext1,
                                             sizeof(kContext1)));

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx_.get(), SSL_SESS_CACHE_BOTH);

  bssl::UniquePtr<SSL_SESSION> session =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());
  ASSERT_TRUE(session);

  TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                  session.get(),
                                  true /* expect session reused */));

  // Change the session ID context.
  ASSERT_TRUE(SSL_CTX_set_session_id_context(server_ctx_.get(), kContext2,
                                             sizeof(kContext2)));

  TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                  session.get(),
                                  false /* expect session not reused */));

  // Change the session ID context back and install an SNI callback to switch
  // it.
  ASSERT_TRUE(SSL_CTX_set_session_id_context(server_ctx_.get(), kContext1,
                                             sizeof(kContext1)));

  SSL_CTX_set_tlsext_servername_callback(server_ctx_.get(),
                                         SwitchSessionIDContextSNI);

  TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                  session.get(),
                                  false /* expect session not reused */));

  // Switch the session ID context with the early callback instead.
  SSL_CTX_set_tlsext_servername_callback(server_ctx_.get(), nullptr);
  SSL_CTX_set_select_certificate_cb(
      server_ctx_.get(),
      [](const SSL_CLIENT_HELLO *client_hello) -> ssl_select_cert_result_t {
        static const uint8_t kContext[] = {3};

        if (!SSL_set_session_id_context(client_hello->ssl, kContext,
                                        sizeof(kContext))) {
          return ssl_select_cert_error;
        }

        return ssl_select_cert_success;
      });

  TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                  session.get(),
                                  false /* expect session not reused */));
}

static timeval g_current_time;

static void CurrentTimeCallback(const SSL *ssl, timeval *out_clock) {
  *out_clock = g_current_time;
}

static void FrozenTimeCallback(const SSL *ssl, timeval *out_clock) {
  out_clock->tv_sec = 1000;
  out_clock->tv_usec = 0;
}

static int RenewTicketCallback(SSL *ssl, uint8_t *key_name, uint8_t *iv,
                               EVP_CIPHER_CTX *ctx, HMAC_CTX *hmac_ctx,
                               int encrypt) {
  static const uint8_t kZeros[16] = {0};

  if (encrypt) {
    OPENSSL_memcpy(key_name, kZeros, sizeof(kZeros));
    RAND_bytes(iv, 16);
  } else if (OPENSSL_memcmp(key_name, kZeros, 16) != 0) {
    return 0;
  }

  if (!HMAC_Init_ex(hmac_ctx, kZeros, sizeof(kZeros), EVP_sha256(), NULL) ||
      !EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, kZeros, iv, encrypt)) {
    return -1;
  }

  // Returning two from the callback in decrypt mode renews the
  // session in TLS 1.2 and below.
  return encrypt ? 1 : 2;
}

static bool GetServerTicketTime(long *out, const SSL_SESSION *session) {
  const uint8_t *ticket;
  size_t ticket_len;
  SSL_SESSION_get0_ticket(session, &ticket, &ticket_len);
  if (ticket_len < 16 + 16 + SHA256_DIGEST_LENGTH) {
    return false;
  }

  const uint8_t *ciphertext = ticket + 16 + 16;
  size_t len = ticket_len - 16 - 16 - SHA256_DIGEST_LENGTH;
  std::unique_ptr<uint8_t[]> plaintext(new uint8_t[len]);

#if defined(BORINGSSL_UNSAFE_FUZZER_MODE)
  // Fuzzer-mode tickets are unencrypted.
  OPENSSL_memcpy(plaintext.get(), ciphertext, len);
#else
  static const uint8_t kZeros[16] = {0};
  const uint8_t *iv = ticket + 16;
  bssl::ScopedEVP_CIPHER_CTX ctx;
  int len1, len2;
  if (len > INT_MAX ||
      !EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr, kZeros, iv) ||
      !EVP_DecryptUpdate(ctx.get(), plaintext.get(), &len1, ciphertext,
                         static_cast<int>(len)) ||
      !EVP_DecryptFinal_ex(ctx.get(), plaintext.get() + len1, &len2)) {
    return false;
  }

  len = static_cast<size_t>(len1 + len2);
#endif

  bssl::UniquePtr<SSL_CTX> ssl_ctx(SSL_CTX_new(TLS_method()));
  if (!ssl_ctx) {
    return false;
  }
  bssl::UniquePtr<SSL_SESSION> server_session(
      SSL_SESSION_from_bytes(plaintext.get(), len, ssl_ctx.get()));
  if (!server_session) {
    return false;
  }

  *out = SSL_SESSION_get_time(server_session.get());
  return true;
}

TEST_P(SSLVersionTest, SessionTimeout) {
  for (bool server_test : {false, true}) {
    SCOPED_TRACE(server_test);

    ASSERT_NO_FATAL_FAILURE(ResetContexts());
    SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
    SSL_CTX_set_session_cache_mode(server_ctx_.get(), SSL_SESS_CACHE_BOTH);

    static const time_t kStartTime = 1000;
    g_current_time.tv_sec = kStartTime;

    // We are willing to use a longer lifetime for TLS 1.3 sessions as
    // resumptions still perform ECDHE.
    const time_t timeout = version() == TLS1_3_VERSION
                               ? SSL_DEFAULT_SESSION_PSK_DHE_TIMEOUT
                               : SSL_DEFAULT_SESSION_TIMEOUT;

    // Both client and server must enforce session timeouts. We configure the
    // other side with a frozen clock so it never expires tickets.
    if (server_test) {
      SSL_CTX_set_current_time_cb(client_ctx_.get(), FrozenTimeCallback);
      SSL_CTX_set_current_time_cb(server_ctx_.get(), CurrentTimeCallback);
    } else {
      SSL_CTX_set_current_time_cb(client_ctx_.get(), CurrentTimeCallback);
      SSL_CTX_set_current_time_cb(server_ctx_.get(), FrozenTimeCallback);
    }

    // Configure a ticket callback which renews tickets.
    SSL_CTX_set_tlsext_ticket_key_cb(server_ctx_.get(), RenewTicketCallback);

    bssl::UniquePtr<SSL_SESSION> session =
        CreateClientSession(client_ctx_.get(), server_ctx_.get());
    ASSERT_TRUE(session);

    // Advance the clock just behind the timeout.
    g_current_time.tv_sec += timeout - 1;

    TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                    session.get(),
                                    true /* expect session reused */));

    // Advance the clock one more second.
    g_current_time.tv_sec++;

    TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                    session.get(),
                                    false /* expect session not reused */));

    // Rewind the clock to before the session was minted.
    g_current_time.tv_sec = kStartTime - 1;

    TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                    session.get(),
                                    false /* expect session not reused */));

    // Renew the session 10 seconds before expiration.
    time_t new_start_time = kStartTime + timeout - 10;
    g_current_time.tv_sec = new_start_time;
    bssl::UniquePtr<SSL_SESSION> new_session = ExpectSessionRenewed(
        client_ctx_.get(), server_ctx_.get(), session.get());
    ASSERT_TRUE(new_session);

    // This new session is not the same object as before.
    EXPECT_NE(session.get(), new_session.get());

    // Check the sessions have timestamps measured from issuance.
    long session_time = 0;
    if (server_test) {
      ASSERT_TRUE(GetServerTicketTime(&session_time, new_session.get()));
    } else {
      session_time = SSL_SESSION_get_time(new_session.get());
    }

    ASSERT_EQ(session_time, g_current_time.tv_sec);

    if (version() == TLS1_3_VERSION) {
      // Renewal incorporates fresh key material in TLS 1.3, so we extend the
      // lifetime TLS 1.3.
      g_current_time.tv_sec = new_start_time + timeout - 1;
      TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                      new_session.get(),
                                      true /* expect session reused */));

      // The new session expires after the new timeout.
      g_current_time.tv_sec = new_start_time + timeout + 1;
      TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                      new_session.get(),
                                      false /* expect session ot reused */));

      // Renew the session until it begins just past the auth timeout.
      time_t auth_end_time = kStartTime + SSL_DEFAULT_SESSION_AUTH_TIMEOUT;
      while (new_start_time < auth_end_time - 1000) {
        // Get as close as possible to target start time.
        new_start_time =
            std::min(auth_end_time - 1000, new_start_time + timeout - 1);
        g_current_time.tv_sec = new_start_time;
        new_session = ExpectSessionRenewed(client_ctx_.get(), server_ctx_.get(),
                                           new_session.get());
        ASSERT_TRUE(new_session);
      }

      // Now the session's lifetime is bound by the auth timeout.
      g_current_time.tv_sec = auth_end_time - 1;
      TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                      new_session.get(),
                                      true /* expect session reused */));

      g_current_time.tv_sec = auth_end_time + 1;
      TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                      new_session.get(),
                                      false /* expect session ot reused */));
    } else {
      // The new session is usable just before the old expiration.
      g_current_time.tv_sec = kStartTime + timeout - 1;
      TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                      new_session.get(),
                                      true /* expect session reused */));

      // Renewal does not extend the lifetime, so it is not usable beyond the
      // old expiration.
      g_current_time.tv_sec = kStartTime + timeout + 1;
      TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                      new_session.get(),
                                      false /* expect session not reused */));
    }
  }
}

TEST_P(SSLVersionTest, DefaultTicketKeyInitialization) {
  // Do not make static and const. See t/P118709392.
  // It can trigger https://gcc.gnu.org/bugzilla/show_bug.cgi?id=95189 leading
  // to transient errors.
  uint8_t kZeroKey[kTicketKeyLen] = {0};
  uint8_t ticket_key[kTicketKeyLen];
  ASSERT_EQ(1, SSL_CTX_get_tlsext_ticket_keys(server_ctx_.get(), ticket_key,
                                              kTicketKeyLen));
  ASSERT_NE(0, OPENSSL_memcmp(ticket_key, kZeroKey, kTicketKeyLen));
}

TEST_P(SSLVersionTest, DefaultTicketKeyRotation) {
  static const time_t kStartTime = 1001;
  g_current_time.tv_sec = kStartTime;

  // We use session reuse as a proxy for ticket decryption success, hence
  // disable session timeouts.
  SSL_CTX_set_timeout(server_ctx_.get(), std::numeric_limits<uint32_t>::max());
  SSL_CTX_set_session_psk_dhe_timeout(server_ctx_.get(),
                                      std::numeric_limits<uint32_t>::max());

  SSL_CTX_set_current_time_cb(client_ctx_.get(), FrozenTimeCallback);
  SSL_CTX_set_current_time_cb(server_ctx_.get(), CurrentTimeCallback);

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx_.get(), SSL_SESS_CACHE_OFF);

  // Initialize ticket_key with the current key and check that it was
  // initialized to something, not all zeros.
  uint8_t ticket_key[kTicketKeyLen] = {0};
  TRACED_CALL(ExpectTicketKeyChanged(server_ctx_.get(), ticket_key,
                                     true /* changed */));

  // Verify ticket resumption actually works.
  bssl::UniquePtr<SSL> client, server;
  bssl::UniquePtr<SSL_SESSION> session =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());
  ASSERT_TRUE(session);
  TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                  session.get(), true /* reused */));

  // Advance time to just before key rotation.
  g_current_time.tv_sec += SSL_DEFAULT_TICKET_KEY_ROTATION_INTERVAL - 1;
  TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                  session.get(), true /* reused */));
  TRACED_CALL(ExpectTicketKeyChanged(server_ctx_.get(), ticket_key,
                                     false /* NOT changed */));

  // Force key rotation.
  g_current_time.tv_sec += 1;
  bssl::UniquePtr<SSL_SESSION> new_session =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());
  TRACED_CALL(ExpectTicketKeyChanged(server_ctx_.get(), ticket_key,
                                     true /* changed */));

  // Resumption with both old and new ticket should work.
  TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                  session.get(), true /* reused */));
  TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                  new_session.get(), true /* reused */));
  TRACED_CALL(ExpectTicketKeyChanged(server_ctx_.get(), ticket_key,
                                     false /* NOT changed */));

  // Force key rotation again. Resumption with the old ticket now fails.
  g_current_time.tv_sec += SSL_DEFAULT_TICKET_KEY_ROTATION_INTERVAL;
  TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                  session.get(), false /* NOT reused */));
  TRACED_CALL(ExpectTicketKeyChanged(server_ctx_.get(), ticket_key,
                                     true /* changed */));

  // But resumption with the newer session still works.
  TRACED_CALL(ExpectSessionReused(client_ctx_.get(), server_ctx_.get(),
                                  new_session.get(), true /* reused */));
}

static int SwitchContext(SSL *ssl, int *out_alert, void *arg) {
  SSL_CTX *ctx = reinterpret_cast<SSL_CTX *>(arg);
  SSL_set_SSL_CTX(ssl, ctx);
  return SSL_TLSEXT_ERR_OK;
}

TEST_P(SSLVersionTest, SNICallback) {
  bssl::UniquePtr<X509> cert2 = GetECDSATestCertificate();
  ASSERT_TRUE(cert2);
  bssl::UniquePtr<EVP_PKEY> key2 = GetECDSATestKey();
  ASSERT_TRUE(key2);

  // Test that switching the |SSL_CTX| at the SNI callback behaves correctly.
  static const uint16_t kECDSAWithSHA256 = SSL_SIGN_ECDSA_SECP256R1_SHA256;

  static const uint8_t kSCTList[] = {0, 6, 0, 4, 5, 6, 7, 8};
  static const uint8_t kOCSPResponse[] = {1, 2, 3, 4};

  bssl::UniquePtr<SSL_CTX> server_ctx2 = CreateContext();
  ASSERT_TRUE(server_ctx2);
  ASSERT_TRUE(SSL_CTX_use_certificate(server_ctx2.get(), cert2.get()));
  ASSERT_TRUE(SSL_CTX_use_PrivateKey(server_ctx2.get(), key2.get()));
  ASSERT_TRUE(SSL_CTX_set_signed_cert_timestamp_list(
      server_ctx2.get(), kSCTList, sizeof(kSCTList)));
  ASSERT_TRUE(SSL_CTX_set_ocsp_response(server_ctx2.get(), kOCSPResponse,
                                        sizeof(kOCSPResponse)));
  // Historically signing preferences would be lost in some cases with the
  // SNI callback, which triggers the TLS 1.2 SHA-1 default. To ensure
  // this doesn't happen when |version| is TLS 1.2, configure the private
  // key to only sign SHA-256.
  ASSERT_TRUE(SSL_CTX_set_signing_algorithm_prefs(server_ctx2.get(),
                                                  &kECDSAWithSHA256, 1));

  SSL_CTX_set_tlsext_servername_callback(server_ctx_.get(), SwitchContext);
  SSL_CTX_set_tlsext_servername_arg(server_ctx_.get(), server_ctx2.get());

  SSL_CTX_enable_signed_cert_timestamps(client_ctx_.get());
  SSL_CTX_enable_ocsp_stapling(client_ctx_.get());

  ASSERT_TRUE(Connect());

  // The client should have received |cert2|.
  bssl::UniquePtr<X509> peer(SSL_get_peer_certificate(client_.get()));
  ASSERT_TRUE(peer);
  EXPECT_EQ(X509_cmp(peer.get(), cert2.get()), 0);

  // The client should have received |server_ctx2|'s SCT list.
  const uint8_t *data;
  size_t len;
  SSL_get0_signed_cert_timestamp_list(client_.get(), &data, &len);
  EXPECT_EQ(Bytes(kSCTList), Bytes(data, len));

  // The client should have received |server_ctx2|'s OCSP response.
  SSL_get0_ocsp_response(client_.get(), &data, &len);
  EXPECT_EQ(Bytes(kOCSPResponse), Bytes(data, len));
}

// Test that the early callback can swap the maximum version.
TEST(SSLTest, EarlyCallbackVersionSwitch) {
  bssl::UniquePtr<SSL_CTX> server_ctx =
      CreateContextWithTestCertificate(TLS_method());
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(server_ctx);
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_3_VERSION));

  SSL_CTX_set_select_certificate_cb(
      server_ctx.get(),
      [](const SSL_CLIENT_HELLO *client_hello) -> ssl_select_cert_result_t {
        if (!SSL_set_max_proto_version(client_hello->ssl, TLS1_2_VERSION)) {
          return ssl_select_cert_error;
        }

        return ssl_select_cert_success;
      });

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));
  EXPECT_EQ(TLS1_2_VERSION, SSL_version(client.get()));
}

TEST(SSLTest, SetVersion) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);

  // Set valid TLS versions.
  for (const auto &vers : kAllVersions) {
    SCOPED_TRACE(vers.name);
    if (vers.ssl_method == VersionParam::is_tls) {
      EXPECT_TRUE(SSL_CTX_set_max_proto_version(ctx.get(), vers.version));
      EXPECT_EQ(SSL_CTX_get_max_proto_version(ctx.get()), vers.version);
      EXPECT_TRUE(SSL_CTX_set_min_proto_version(ctx.get(), vers.version));
      EXPECT_EQ(SSL_CTX_get_min_proto_version(ctx.get()), vers.version);
      EXPECT_TRUE(SSL_set_max_proto_version(ssl.get(), vers.version));
      EXPECT_EQ(SSL_get_max_proto_version(ssl.get()), vers.version);
      EXPECT_TRUE(SSL_set_min_proto_version(ssl.get(), vers.version));
      EXPECT_EQ(SSL_get_min_proto_version(ssl.get()), vers.version);
    }
  }

  // Invalid TLS versions are rejected.
  EXPECT_FALSE(SSL_CTX_set_max_proto_version(ctx.get(), DTLS1_VERSION));
  EXPECT_FALSE(SSL_CTX_set_max_proto_version(ctx.get(), 0x0200));
  EXPECT_FALSE(SSL_CTX_set_max_proto_version(ctx.get(), 0x1234));
  EXPECT_FALSE(SSL_CTX_set_min_proto_version(ctx.get(), DTLS1_VERSION));
  EXPECT_FALSE(SSL_CTX_set_min_proto_version(ctx.get(), 0x0200));
  EXPECT_FALSE(SSL_CTX_set_min_proto_version(ctx.get(), 0x1234));
  EXPECT_FALSE(SSL_set_max_proto_version(ssl.get(), 0x0200));
  EXPECT_FALSE(SSL_set_max_proto_version(ssl.get(), 0x1234));
  EXPECT_FALSE(SSL_set_min_proto_version(ssl.get(), DTLS1_VERSION));
  EXPECT_FALSE(SSL_set_min_proto_version(ssl.get(), 0x0200));
  EXPECT_FALSE(SSL_set_min_proto_version(ssl.get(), 0x1234));

  // Zero represents the default version.
  EXPECT_TRUE(SSL_CTX_set_max_proto_version(ctx.get(), 0));
  EXPECT_EQ(0, SSL_CTX_get_max_proto_version(ctx.get()));
  EXPECT_TRUE(SSL_CTX_set_min_proto_version(ctx.get(), 0));
  EXPECT_EQ(0, SSL_CTX_get_min_proto_version(ctx.get()));
  EXPECT_TRUE(SSL_set_max_proto_version(ssl.get(), 0));
  EXPECT_EQ(0, SSL_get_max_proto_version(ssl.get()));
  EXPECT_TRUE(SSL_set_min_proto_version(ssl.get(), 0));
  EXPECT_EQ(0, SSL_get_min_proto_version(ssl.get()));

  // SSL 3.0 is not available.
  EXPECT_FALSE(SSL_CTX_set_min_proto_version(ctx.get(), SSL3_VERSION));
  EXPECT_FALSE(SSL_set_min_proto_version(ssl.get(), SSL3_VERSION));

  ctx.reset(SSL_CTX_new(DTLS_method()));
  ASSERT_TRUE(ctx);
  ssl.reset(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);

  // Set valid DTLS versions.
  for (const auto &vers : kAllVersions) {
    SCOPED_TRACE(vers.name);
    if (vers.ssl_method == VersionParam::is_dtls) {
      EXPECT_TRUE(SSL_CTX_set_max_proto_version(ctx.get(), vers.version));
      EXPECT_EQ(SSL_CTX_get_max_proto_version(ctx.get()), vers.version);
      EXPECT_TRUE(SSL_CTX_set_min_proto_version(ctx.get(), vers.version));
      EXPECT_EQ(SSL_CTX_get_min_proto_version(ctx.get()), vers.version);
    }
  }

  // Invalid DTLS versions are rejected.
  EXPECT_FALSE(SSL_CTX_set_max_proto_version(ctx.get(), TLS1_VERSION));
  EXPECT_FALSE(SSL_CTX_set_max_proto_version(ctx.get(), 0xfefe /* DTLS 1.1 */));
  EXPECT_FALSE(SSL_CTX_set_max_proto_version(ctx.get(), 0xfffe /* DTLS 0.1 */));
  EXPECT_FALSE(SSL_CTX_set_max_proto_version(ctx.get(), 0x1234));
  EXPECT_FALSE(SSL_CTX_set_min_proto_version(ctx.get(), TLS1_VERSION));
  EXPECT_FALSE(SSL_CTX_set_min_proto_version(ctx.get(), 0xfefe /* DTLS 1.1 */));
  EXPECT_FALSE(SSL_CTX_set_min_proto_version(ctx.get(), 0xfffe /* DTLS 0.1 */));
  EXPECT_FALSE(SSL_CTX_set_min_proto_version(ctx.get(), 0x1234));

  // Zero represents the default version.
  EXPECT_TRUE(SSL_CTX_set_max_proto_version(ctx.get(), 0));
  EXPECT_EQ(0, SSL_CTX_get_max_proto_version(ctx.get()));
  EXPECT_TRUE(SSL_CTX_set_min_proto_version(ctx.get(), 0));
  EXPECT_EQ(0, SSL_CTX_get_min_proto_version(ctx.get()));
}

static const char *GetVersionName(uint16_t version) {
  switch (version) {
    case TLS1_VERSION:
      return "TLSv1";
    case TLS1_1_VERSION:
      return "TLSv1.1";
    case TLS1_2_VERSION:
      return "TLSv1.2";
    case TLS1_3_VERSION:
      return "TLSv1.3";
    case DTLS1_VERSION:
      return "DTLSv1";
    case DTLS1_2_VERSION:
      return "DTLSv1.2";
    default:
      return "???";
  }
}

TEST_P(SSLVersionTest, Version) {
  ASSERT_TRUE(Connect());

  EXPECT_EQ(SSL_version(client_.get()), version());
  EXPECT_EQ(SSL_version(server_.get()), version());

  // Test the version name is reported as expected.
  const char *version_name = GetVersionName(version());
  EXPECT_EQ(strcmp(version_name, SSL_get_version(client_.get())), 0);
  EXPECT_EQ(strcmp(version_name, SSL_get_version(server_.get())), 0);

  // Test SSL_SESSION reports the same name.
  const char *client_name =
      SSL_SESSION_get_version(SSL_get_session(client_.get()));
  const char *server_name =
      SSL_SESSION_get_version(SSL_get_session(server_.get()));
  EXPECT_EQ(strcmp(version_name, client_name), 0);
  EXPECT_EQ(strcmp(version_name, server_name), 0);

  // Client/server version equality asserted above, assert equality for cipher here.
  ASSERT_TRUE(SSL_get_current_cipher(client_.get()));
  ASSERT_TRUE(SSL_get_current_cipher(server_.get()));
  EXPECT_EQ(SSL_get_current_cipher(client_.get())->id, SSL_get_current_cipher(server_.get())->id);
  const uint16_t version = SSL_version(client_.get());
  if (version == TLS1_2_VERSION || version == TLS1_3_VERSION) {
    const char *version_str = SSL_get_version(client_.get());
    EXPECT_STREQ(version_str, SSL_CIPHER_get_version(SSL_get_current_cipher(client_.get())));
  } else if (version == DTLS1_2_VERSION) {    // ciphers don't differentiate D/TLS
    EXPECT_STREQ("TLSv1.2", SSL_CIPHER_get_version(SSL_get_current_cipher(client_.get())));
  } else {
    EXPECT_STREQ("TLSv1/SSLv3", SSL_CIPHER_get_version(SSL_get_current_cipher(client_.get())));
  }
}

// Tests that that |SSL_get_pending_cipher| is available during the ALPN
// selection callback.
TEST_P(SSLVersionTest, ALPNCipherAvailable) {
  ASSERT_TRUE(UseCertAndKey(client_ctx_.get()));

  static const uint8_t kALPNProtos[] = {0x03, 'f', 'o', 'o'};
  ASSERT_EQ(SSL_CTX_set_alpn_protos(client_ctx_.get(), kALPNProtos,
                                    sizeof(kALPNProtos)),
            0);

  // The ALPN callback does not fail the handshake on error, so have the
  // callback write a boolean.
  std::pair<uint16_t, bool> callback_state(version(), false);
  SSL_CTX_set_alpn_select_cb(
      server_ctx_.get(),
      [](SSL *ssl, const uint8_t **out, uint8_t *out_len, const uint8_t *in,
         unsigned in_len, void *arg) -> int {
        auto state = reinterpret_cast<std::pair<uint16_t, bool> *>(arg);
        if (SSL_get_pending_cipher(ssl) != nullptr &&
            SSL_version(ssl) == state->first) {
          state->second = true;
        }
        return SSL_TLSEXT_ERR_NOACK;
      },
      &callback_state);

  ASSERT_TRUE(Connect());

  ASSERT_TRUE(callback_state.second);
}

TEST_P(SSLVersionTest, SSLClearSessionResumption) {
  // Skip this for TLS 1.3. TLS 1.3's ticket mechanism is incompatible with this
  // API pattern.
  if (version() == TLS1_3_VERSION) {
    return;
  }

  shed_handshake_config_ = false;
  ASSERT_TRUE(Connect());

  EXPECT_FALSE(SSL_session_reused(client_.get()));
  EXPECT_FALSE(SSL_session_reused(server_.get()));

  // Reset everything.
  ASSERT_TRUE(SSL_clear(client_.get()));
  ASSERT_TRUE(SSL_clear(server_.get()));

  // Attempt to connect a second time.
  ASSERT_TRUE(CompleteHandshakes(client_.get(), server_.get()));

  // |SSL_clear| should implicitly offer the previous session to the server.
  EXPECT_TRUE(SSL_session_reused(client_.get()));
  EXPECT_TRUE(SSL_session_reused(server_.get()));
}

TEST_P(SSLVersionTest, SSLClearFailsWithShedding) {
  shed_handshake_config_ = false;
  ASSERT_TRUE(Connect());
  ASSERT_TRUE(CompleteHandshakes(client_.get(), server_.get()));

  // Reset everything.
  ASSERT_TRUE(SSL_clear(client_.get()));
  ASSERT_TRUE(SSL_clear(server_.get()));

  // Now enable shedding, and connect a second time.
  shed_handshake_config_ = true;
  ASSERT_TRUE(Connect());
  ASSERT_TRUE(CompleteHandshakes(client_.get(), server_.get()));

  // |SSL_clear| should now fail.
  ASSERT_FALSE(SSL_clear(client_.get()));
  ASSERT_FALSE(SSL_clear(server_.get()));
}

TEST_P(SSLVersionTest, SSLClientCiphers) {
  // Client ciphers ARE NOT SERIALIZED, so skip tests that rely on transfer or
  // serialization of |ssl| and accompanying objects under test.
  if (getVersionParam().transfer_ssl) {
      return;
  }

  EXPECT_FALSE(SSL_get_client_ciphers(client_.get()));
  EXPECT_FALSE(SSL_get_client_ciphers(server_.get()));

  shed_handshake_config_ = false;
  ASSERT_TRUE(Connect());

  // The client should still have no view of the server's preferences, but the
  // server should have seen at least one cipher from the client.
  EXPECT_FALSE(SSL_get_client_ciphers(client_.get()));
  EXPECT_GT(sk_SSL_CIPHER_num(SSL_get_client_ciphers(server_.get())), (size_t) 0);

  // With config shedding disabled, clearing |server| shouldn't error and
  // should reset server's client ciphers
  ASSERT_TRUE(SSL_clear(server_.get()));
  EXPECT_FALSE(SSL_get_client_ciphers(server_.get()));

  shed_handshake_config_ = true;
  ASSERT_TRUE(Connect());

  // These should be unaffected by config shedding
  EXPECT_FALSE(SSL_get_client_ciphers(client_.get()));
  EXPECT_GT(sk_SSL_CIPHER_num(SSL_get_client_ciphers(server_.get())), (size_t) 0);
}

static bool ChainsEqual(STACK_OF(X509) *chain,
                        const std::vector<X509 *> &expected) {
  if (sk_X509_num(chain) != expected.size()) {
    return false;
  }

  for (size_t i = 0; i < expected.size(); i++) {
    if (X509_cmp(sk_X509_value(chain, i), expected[i]) != 0) {
      return false;
    }
  }

  return true;
}

TEST_P(SSLVersionTest, AutoChain) {
  cert_ = GetChainTestCertificate();
  ASSERT_TRUE(cert_);
  key_ = GetChainTestKey();
  ASSERT_TRUE(key_);
  bssl::UniquePtr<X509> intermediate = GetChainTestIntermediate();
  ASSERT_TRUE(intermediate);

  ASSERT_TRUE(UseCertAndKey(client_ctx_.get()));
  ASSERT_TRUE(UseCertAndKey(server_ctx_.get()));

  // Configure both client and server to accept any certificate. Add
  // |intermediate| to the cert store.
  ASSERT_TRUE(X509_STORE_add_cert(SSL_CTX_get_cert_store(client_ctx_.get()),
                                  intermediate.get()));
  ASSERT_TRUE(X509_STORE_add_cert(SSL_CTX_get_cert_store(server_ctx_.get()),
                                  intermediate.get()));
  SSL_CTX_set_verify(client_ctx_.get(),
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     nullptr);
  SSL_CTX_set_verify(server_ctx_.get(),
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     nullptr);
  SSL_CTX_set_cert_verify_callback(client_ctx_.get(), VerifySucceed, NULL);
  SSL_CTX_set_cert_verify_callback(server_ctx_.get(), VerifySucceed, NULL);

  // By default, the client and server should each only send the leaf.
  ASSERT_TRUE(Connect());

  EXPECT_TRUE(
      ChainsEqual(SSL_get_peer_full_cert_chain(client_.get()), {cert_.get()}));
  EXPECT_TRUE(
      ChainsEqual(SSL_get_peer_full_cert_chain(server_.get()), {cert_.get()}));
  // This test overrides the verification logic  with VerifySucceed to always
  // succeed without actually verifying anything and setting the verified chain
  // on success
  EXPECT_EQ(SSL_get0_verified_chain(server_.get()), nullptr);
  EXPECT_EQ(SSL_get0_verified_chain(client_.get()), nullptr);

  // If auto-chaining is enabled, then the intermediate is sent.
  SSL_CTX_clear_mode(client_ctx_.get(), SSL_MODE_NO_AUTO_CHAIN);
  SSL_CTX_clear_mode(server_ctx_.get(), SSL_MODE_NO_AUTO_CHAIN);
  ASSERT_TRUE(Connect());

  EXPECT_TRUE(ChainsEqual(SSL_get_peer_full_cert_chain(client_.get()),
                          {cert_.get(), intermediate.get()}));
  EXPECT_TRUE(ChainsEqual(SSL_get_peer_full_cert_chain(server_.get()),
                          {cert_.get(), intermediate.get()}));

  // Auto-chaining does not override explicitly-configured intermediates.
  ASSERT_TRUE(SSL_CTX_add1_chain_cert(client_ctx_.get(), cert_.get()));
  ASSERT_TRUE(SSL_CTX_add1_chain_cert(server_ctx_.get(), cert_.get()));
  ASSERT_TRUE(Connect());

  EXPECT_TRUE(ChainsEqual(SSL_get_peer_full_cert_chain(client_.get()),
                          {cert_.get(), cert_.get()}));

  EXPECT_TRUE(ChainsEqual(SSL_get_peer_full_cert_chain(server_.get()),
                          {cert_.get(), cert_.get()}));
}

static bool ExpectSingleError(int lib, int reason) {
  const char *expected = ERR_reason_error_string(ERR_PACK(lib, reason));
  int err = ERR_get_error();
  if (ERR_GET_LIB(err) != lib || ERR_GET_REASON(err) != reason) {
    char buf[ERR_ERROR_STRING_BUF_LEN];
    ERR_error_string_n(err, buf, sizeof(buf));
    fprintf(stderr, "Wanted %s, got: %s.\n", expected, buf);
    return false;
  }

  if (ERR_peek_error() != 0) {
    fprintf(stderr, "Unexpected error following %s.\n", expected);
    return false;
  }

  return true;
}

TEST(SSLTest, BuildCertChain) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));

  // No certificate set, so this should fail.
  EXPECT_FALSE(SSL_CTX_build_cert_chain(ctx.get(), 0));
  EXPECT_TRUE(ExpectSingleError(ERR_LIB_SSL, SSL_R_NO_CERTIFICATE_SET));

  ASSERT_TRUE(SSL_CTX_use_certificate(ctx.get(), GetLeafPublic().get()));
  ASSERT_TRUE(SSL_CTX_use_PrivateKey(ctx.get(), GetLeafKey().get()));

  // Verification will fail because there is no valid root cert available.
  EXPECT_FALSE(SSL_CTX_build_cert_chain(ctx.get(), 0));
  ERR_clear_error();

  // Should return 2 when |SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR| is set.
  EXPECT_EQ(
      SSL_CTX_build_cert_chain(ctx.get(), SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR),
      2);
  EXPECT_TRUE(ExpectSingleError(ERR_LIB_SSL, SSL_R_CERTIFICATE_VERIFY_FAILED));
  ERR_clear_error();

  // Should return 2, but with no error on the stack when
  // |SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR| and |SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR|
  // are set.
  EXPECT_EQ(
      SSL_CTX_build_cert_chain(ctx.get(), SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR |
                                              SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR),
      2);
  EXPECT_FALSE(ERR_get_error());

  // Pass in the trust store. |SSL_CTX_build_cert_chain| should succeed now.
  ASSERT_TRUE(X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx.get()),
                                  GetLeafRoot().get()));
  X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(ctx.get()),
                              X509_V_FLAG_NO_CHECK_TIME);
  EXPECT_EQ(SSL_CTX_build_cert_chain(ctx.get(), 0), 1);
  STACK_OF(X509) *chain;
  ASSERT_TRUE(SSL_CTX_get0_chain_certs(ctx.get(), &chain));
  EXPECT_TRUE(ChainsEqual(chain, {GetLeafRoot().get()}));

  // Root cert is self-signed, so |SSL_BUILD_CHAIN_FLAG_UNTRUSTED| will
  // still pass.
  ASSERT_TRUE(SSL_CTX_clear_chain_certs(ctx.get()));
  EXPECT_TRUE(
      SSL_CTX_build_cert_chain(ctx.get(), SSL_BUILD_CHAIN_FLAG_UNTRUSTED));
  ASSERT_TRUE(SSL_CTX_get0_chain_certs(ctx.get(), &chain));
  EXPECT_TRUE(ChainsEqual(chain, {GetLeafRoot().get()}));

  // |SSL_BUILD_CHAIN_FLAG_CHECK| uses the already built cert chain as the trust
  // store and verifies against it. If we clear the cert chain, there should be
  // no trust store to compare against if |SSL_BUILD_CHAIN_FLAG_CHECK| is still
  // set.
  EXPECT_EQ(SSL_CTX_build_cert_chain(ctx.get(), SSL_BUILD_CHAIN_FLAG_CHECK), 1);
  ASSERT_TRUE(SSL_CTX_clear_chain_certs(ctx.get()));
  EXPECT_FALSE(SSL_CTX_build_cert_chain(ctx.get(), SSL_BUILD_CHAIN_FLAG_CHECK));
  EXPECT_TRUE(ExpectSingleError(ERR_LIB_SSL, SSL_R_CERTIFICATE_VERIFY_FAILED));

  // |SSL_BUILD_CHAIN_FLAG_CHECK| and |SSL_BUILD_CHAIN_FLAG_UNTRUSTED| are
  // mutually exclusive, with |SSL_BUILD_CHAIN_FLAG_CHECK| taking priority.
  // The result with both set should be the same as only
  // |SSL_BUILD_CHAIN_FLAG_CHECK| being set.
  ASSERT_TRUE(SSL_CTX_clear_chain_certs(ctx.get()));
  EXPECT_FALSE(SSL_CTX_build_cert_chain(
      ctx.get(), SSL_BUILD_CHAIN_FLAG_CHECK | SSL_BUILD_CHAIN_FLAG_UNTRUSTED));
  EXPECT_FALSE(SSL_CTX_build_cert_chain(ctx.get(), SSL_BUILD_CHAIN_FLAG_CHECK));
  // First call with |SSL_BUILD_CHAIN_FLAG_CHECK| existing will fail, second
  // call with |SSL_BUILD_CHAIN_FLAG_UNTRUSTED| will succeed.
  EXPECT_FALSE(SSL_CTX_build_cert_chain(
      ctx.get(), SSL_BUILD_CHAIN_FLAG_CHECK | SSL_BUILD_CHAIN_FLAG_UNTRUSTED));
  EXPECT_EQ(SSL_CTX_build_cert_chain(ctx.get(), SSL_BUILD_CHAIN_FLAG_UNTRUSTED),
            1);
  // |SSL_BUILD_CHAIN_FLAG_CHECK| will succeed since we have a built chain now.
  EXPECT_EQ(SSL_CTX_build_cert_chain(ctx.get(), SSL_BUILD_CHAIN_FLAG_CHECK), 1);

  // Test that successful verification with |SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR|
  // does not return 2.
  ASSERT_TRUE(SSL_CTX_clear_chain_certs(ctx.get()));
  EXPECT_EQ(
      SSL_CTX_build_cert_chain(ctx.get(), SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR),
      1);

  // Test that successful verification with |SSL_BUILD_CHAIN_FLAG_NO_ROOT|
  // does include the root cert.
  ASSERT_TRUE(SSL_CTX_clear_chain_certs(ctx.get()));
  EXPECT_EQ(SSL_CTX_build_cert_chain(ctx.get(), SSL_BUILD_CHAIN_FLAG_NO_ROOT),
            1);
  ASSERT_TRUE(SSL_CTX_get0_chain_certs(ctx.get(), &chain));
  EXPECT_TRUE(ChainsEqual(chain, {}));
}

TEST_P(SSLVersionTest, SSLWriteRetry) {
  if (is_dtls()) {
    return;
  }

  for (bool enable_partial_write : {false, true}) {
    SCOPED_TRACE(enable_partial_write);

    // Connect a client and server.
    ASSERT_TRUE(Connect());

    if (enable_partial_write) {
      SSL_set_mode(client_.get(), SSL_MODE_ENABLE_PARTIAL_WRITE);
    }

    // Write without reading until the buffer is full and we have an unfinished
    // write. Keep a count so we may reread it again later. "hello!" will be
    // written in two chunks, "hello" and "!".
    char data[] = "hello!";
    static const int kChunkLen = 5;  // The length of "hello".
    unsigned count = 0;
    for (;;) {
      int ret = SSL_write(client_.get(), data, kChunkLen);
      if (ret <= 0) {
        ASSERT_EQ(SSL_get_error(client_.get(), ret), SSL_ERROR_WANT_WRITE);
        break;
      }
      ASSERT_EQ(ret, 5);
      count++;
    }

    // Retrying with the same parameters is legal.
    ASSERT_EQ(
        SSL_get_error(client_.get(), SSL_write(client_.get(), data, kChunkLen)),
        SSL_ERROR_WANT_WRITE);

    // Retrying with the same buffer but shorter length is not legal.
    ASSERT_EQ(SSL_get_error(client_.get(),
                            SSL_write(client_.get(), data, kChunkLen - 1)),
              SSL_ERROR_SSL);
    ASSERT_TRUE(ExpectSingleError(ERR_LIB_SSL, SSL_R_BAD_WRITE_RETRY));

    // Retrying with a different buffer pointer is not legal.
    char data2[] = "hello";
    ASSERT_EQ(SSL_get_error(client_.get(),
                            SSL_write(client_.get(), data2, kChunkLen)),
              SSL_ERROR_SSL);
    ASSERT_TRUE(ExpectSingleError(ERR_LIB_SSL, SSL_R_BAD_WRITE_RETRY));

    // With |SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|, the buffer may move.
    SSL_set_mode(client_.get(), SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    ASSERT_EQ(SSL_get_error(client_.get(),
                            SSL_write(client_.get(), data2, kChunkLen)),
              SSL_ERROR_WANT_WRITE);

    // |SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER| does not disable length checks.
    ASSERT_EQ(SSL_get_error(client_.get(),
                            SSL_write(client_.get(), data2, kChunkLen - 1)),
              SSL_ERROR_SSL);
    ASSERT_TRUE(ExpectSingleError(ERR_LIB_SSL, SSL_R_BAD_WRITE_RETRY));

    // Retrying with a larger buffer is legal.
    ASSERT_EQ(SSL_get_error(client_.get(),
                            SSL_write(client_.get(), data, kChunkLen + 1)),
              SSL_ERROR_WANT_WRITE);

    // Drain the buffer.
    char buf[20];
    for (unsigned i = 0; i < count; i++) {
      ASSERT_EQ(SSL_read(server_.get(), buf, sizeof(buf)), kChunkLen);
      ASSERT_EQ(OPENSSL_memcmp(buf, "hello", kChunkLen), 0);
    }

    // Now that there is space, a retry with a larger buffer should flush the
    // pending record, skip over that many bytes of input (on assumption they
    // are the same), and write the remainder. If SSL_MODE_ENABLE_PARTIAL_WRITE
    // is set, this will complete in two steps.
    char data_longer[] = "_____!!!!!";
    if (enable_partial_write) {
      ASSERT_EQ(SSL_write(client_.get(), data_longer, 2 * kChunkLen),
                kChunkLen);
      ASSERT_EQ(SSL_write(client_.get(), data_longer + kChunkLen, kChunkLen),
                kChunkLen);
    } else {
      ASSERT_EQ(SSL_write(client_.get(), data_longer, 2 * kChunkLen),
                2 * kChunkLen);
    }

    // Check the last write was correct. The data will be spread over two
    // records, so SSL_read returns twice.
    ASSERT_EQ(SSL_read(server_.get(), buf, sizeof(buf)), kChunkLen);
    ASSERT_EQ(OPENSSL_memcmp(buf, "hello", kChunkLen), 0);
    ASSERT_EQ(SSL_read(server_.get(), buf, sizeof(buf)), kChunkLen);
    ASSERT_EQ(OPENSSL_memcmp(buf, "!!!!!", kChunkLen), 0);

    // Fill the transport buffer again. This time only leave room for one
    // record.
    count = 0;
    for (;;) {
      int ret = SSL_write(client_.get(), data, kChunkLen);
      if (ret <= 0) {
        ASSERT_EQ(SSL_get_error(client_.get(), ret), SSL_ERROR_WANT_WRITE);
        break;
      }
      ASSERT_EQ(ret, 5);
      count++;
    }
    ASSERT_EQ(SSL_read(server_.get(), buf, sizeof(buf)), kChunkLen);
    ASSERT_EQ(OPENSSL_memcmp(buf, "hello", kChunkLen), 0);
    count--;

    // Retry the last write, with a longer input. The first half is the most
    // recently failed write, from filling the buffer. |SSL_write| should write
    // that to the transport, and then attempt to write the second half.
    int ret = SSL_write(client_.get(), data_longer, 2 * kChunkLen);
    if (enable_partial_write) {
      // If partial writes are allowed, the write will succeed partially.
      ASSERT_EQ(ret, kChunkLen);

      // Check the first half and make room for another record.
      ASSERT_EQ(SSL_read(server_.get(), buf, sizeof(buf)), kChunkLen);
      ASSERT_EQ(OPENSSL_memcmp(buf, "hello", kChunkLen), 0);
      count--;

      // Finish writing the input.
      ASSERT_EQ(SSL_write(client_.get(), data_longer + kChunkLen, kChunkLen),
                kChunkLen);
    } else {
      if (enable_read_ahead()) {
        // The client and server are sharing a BIO_pair which by default only
        // allows 17 * 1024 bytes to be buffered in the shared BIO. This test
        // relies on the buffer being full here. But if the client is reading
        // ahead it is pulling data out of the BIO_pair's buffer and into it's
        // own SSLBuffer freeing up space for the write above
        ASSERT_EQ(ret, 2 * kChunkLen);
      } else {
        // Otherwise, although the first half made it to the transport, the second
        // half is blocked.
        ASSERT_EQ(ret, -1);
        ASSERT_EQ(SSL_get_error(client_.get(), -1), SSL_ERROR_WANT_WRITE);
        // Check the first half and make room for another record.
        ASSERT_EQ(SSL_read(server_.get(), buf, sizeof(buf)), kChunkLen);
        ASSERT_EQ(OPENSSL_memcmp(buf, "hello", kChunkLen), 0);
        count--;

        // Retrying with fewer bytes than previously attempted is an error. If the
        // input length is less than the number of bytes successfully written, the
        // check happens at a different point, with a different error.
        //
        // TODO(davidben): Should these cases use the same error?
        ASSERT_EQ(
            SSL_get_error(client_.get(),
                          SSL_write(client_.get(), data_longer, kChunkLen - 1)),
            SSL_ERROR_SSL);
        ASSERT_TRUE(ExpectSingleError(ERR_LIB_SSL, SSL_R_BAD_LENGTH));

        // Complete the write with the correct retry.
        ASSERT_EQ(SSL_write(client_.get(), data_longer, 2 * kChunkLen),
                  2 * kChunkLen);
      }
    }

    // Drain the input and ensure everything was written correctly.
    for (unsigned i = 0; i < count; i++) {
      ASSERT_EQ(SSL_read(server_.get(), buf, sizeof(buf)), kChunkLen);
      ASSERT_EQ(OPENSSL_memcmp(buf, "hello", kChunkLen), 0);
    }

    // The final write is spread over two records.
    ASSERT_EQ(SSL_read(server_.get(), buf, sizeof(buf)), kChunkLen);
    ASSERT_EQ(OPENSSL_memcmp(buf, "hello", kChunkLen), 0);
    ASSERT_EQ(SSL_read(server_.get(), buf, sizeof(buf)), kChunkLen);
    ASSERT_EQ(OPENSSL_memcmp(buf, "!!!!!", kChunkLen), 0);
  }
}

TEST_P(SSLVersionTest, RecordCallback) {
  for (bool test_server : {true, false}) {
    SCOPED_TRACE(test_server);
    ASSERT_NO_FATAL_FAILURE(ResetContexts());

    bool read_seen = false;
    bool write_seen = false;
    auto cb = [&](int is_write, int cb_version, int cb_type, const void *buf,
                  size_t len, SSL *ssl) {
      if (cb_type != SSL3_RT_HEADER) {
        return;
      }

      // The callback does not report a version for records.
      EXPECT_EQ(0, cb_version);

      if (is_write) {
        write_seen = true;
      } else {
        read_seen = true;
      }

      // Sanity-check that the record header is plausible.
      CBS cbs;
      CBS_init(&cbs, reinterpret_cast<const uint8_t *>(buf), len);
      uint8_t type;
      uint16_t record_version, length;
      ASSERT_TRUE(CBS_get_u8(&cbs, &type));
      ASSERT_TRUE(CBS_get_u16(&cbs, &record_version));
      EXPECT_EQ(record_version & 0xff00, version() & 0xff00);
      if (is_dtls()) {
        uint16_t epoch;
        ASSERT_TRUE(CBS_get_u16(&cbs, &epoch));
        EXPECT_TRUE(epoch == 0 || epoch == 1) << "Invalid epoch: " << epoch;
        ASSERT_TRUE(CBS_skip(&cbs, 6));
      }
      ASSERT_TRUE(CBS_get_u16(&cbs, &length));
      EXPECT_EQ(0u, CBS_len(&cbs));
    };
    using CallbackType = decltype(cb);
    SSL_CTX *ctx = test_server ? server_ctx_.get() : client_ctx_.get();
    SSL_CTX_set_msg_callback(
        ctx, [](int is_write, int cb_version, int cb_type, const void *buf,
                size_t len, SSL *ssl, void *arg) {
          CallbackType *cb_ptr = reinterpret_cast<CallbackType *>(arg);
          (*cb_ptr)(is_write, cb_version, cb_type, buf, len, ssl);
        });
    SSL_CTX_set_msg_callback_arg(ctx, &cb);

    ASSERT_TRUE(Connect());

    EXPECT_TRUE(read_seen);
    EXPECT_TRUE(write_seen);
  }
}

TEST_P(SSLVersionTest, GetServerName) {
  ClientConfig config;
  config.servername = "host1";

  SSL_CTX_set_tlsext_servername_callback(
      server_ctx_.get(), [](SSL *ssl, int *out_alert, void *arg) -> int {
        // During the handshake, |SSL_get_servername| must match |config|.
        ClientConfig *config_p = reinterpret_cast<ClientConfig *>(arg);
        EXPECT_STREQ(config_p->servername.c_str(),
                     SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name));
        return SSL_TLSEXT_ERR_OK;
      });
  SSL_CTX_set_tlsext_servername_arg(server_ctx_.get(), &config);

  ASSERT_TRUE(Connect(config));
  // After the handshake, it must also be available.
  EXPECT_STREQ(config.servername.c_str(),
               SSL_get_servername(server_.get(), TLSEXT_NAMETYPE_host_name));

  // Establish a session under host1.
  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx_.get(), SSL_SESS_CACHE_BOTH);
  bssl::UniquePtr<SSL_SESSION> session =
      CreateClientSession(client_ctx_.get(), server_ctx_.get(), config);

  // If the client resumes a session with a different name, |SSL_get_servername|
  // must return the new name.
  ASSERT_TRUE(session);
  config.session = session.get();
  config.servername = "host2";
  ASSERT_TRUE(Connect(config));
  EXPECT_STREQ(config.servername.c_str(),
               SSL_get_servername(server_.get(), TLSEXT_NAMETYPE_host_name));
}

TEST_P(SSLVersionTest, GetState) {
  ClientConfig config;
  ASSERT_TRUE(Connect(config));
  int server_state = SSL_get_state(server_.get());
  EXPECT_EQ(server_state, TLS_ST_OK);
  EXPECT_EQ(server_state, SSL_ST_OK);
  int client_state = SSL_state(client_.get());
  EXPECT_EQ(client_state, TLS_ST_OK);
  EXPECT_EQ(client_state, SSL_ST_OK);
}

// Test that session cache mode bits are honored in the client session callback.
TEST_P(SSLVersionTest, ClientSessionCacheMode) {
  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_OFF);
  EXPECT_FALSE(CreateClientSession(client_ctx_.get(), server_ctx_.get()));

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_CLIENT);
  EXPECT_TRUE(CreateClientSession(client_ctx_.get(), server_ctx_.get()));

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_SERVER);
  EXPECT_FALSE(CreateClientSession(client_ctx_.get(), server_ctx_.get()));
}

// Test that all versions survive tiny write buffers. In particular, TLS 1.3
// NewSessionTickets are written post-handshake. Servers that block
// |SSL_do_handshake| on writing them will deadlock if clients are not draining
// the buffer. Test that we do not do this.
TEST_P(SSLVersionTest, SmallBuffer) {
  // DTLS is a datagram protocol and requires packet-sized buffers.
  if (is_dtls()) {
    return;
  }

  // Test both flushing NewSessionTickets with a zero-sized write and
  // non-zero-sized write.
  for (bool use_zero_write : {false, true}) {
    SCOPED_TRACE(use_zero_write);

    g_last_session = nullptr;
    SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
    SSL_CTX_sess_set_new_cb(client_ctx_.get(), SaveLastSession);

    bssl::UniquePtr<SSL> client(SSL_new(client_ctx_.get())),
        server(SSL_new(server_ctx_.get()));
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    SSL_set_connect_state(client.get());
    SSL_set_accept_state(server.get());

    // Use a tiny buffer.
    BIO *bio1, *bio2;
    ASSERT_TRUE(BIO_new_bio_pair(&bio1, 1, &bio2, 1));

    // SSL_set_bio takes ownership.
    SSL_set_bio(client.get(), bio1, bio1);
    SSL_set_bio(server.get(), bio2, bio2);

    ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));
    if (version() >= TLS1_3_VERSION) {
      // The post-handshake ticket should not have been processed yet.
      EXPECT_FALSE(g_last_session);
    }

    if (use_zero_write) {
      ASSERT_TRUE(FlushNewSessionTickets(client.get(), server.get()));
      EXPECT_TRUE(g_last_session);
    }

    // Send some data from server to client. If |use_zero_write| is false, this
    // will also flush the NewSessionTickets.
    static const char kMessage[] = "hello world";
    char buf[sizeof(kMessage)];
    for (;;) {
      int server_ret = SSL_write(server.get(), kMessage, sizeof(kMessage));
      int server_err = SSL_get_error(server.get(), server_ret);
      int client_ret = SSL_read(client.get(), buf, sizeof(buf));
      int client_err = SSL_get_error(client.get(), client_ret);

      // The server will write a single record, so every iteration should see
      // |SSL_ERROR_WANT_WRITE| and |SSL_ERROR_WANT_READ|, until the final
      // iteration, where both will complete.
      if (server_ret > 0) {
        EXPECT_EQ(server_ret, static_cast<int>(sizeof(kMessage)));
        EXPECT_EQ(client_ret, static_cast<int>(sizeof(kMessage)));
        EXPECT_EQ(Bytes(buf), Bytes(kMessage));
        break;
      }

      ASSERT_EQ(server_ret, -1);
      ASSERT_EQ(server_err, SSL_ERROR_WANT_WRITE);
      ASSERT_EQ(client_ret, -1);
      ASSERT_EQ(client_err, SSL_ERROR_WANT_READ);
    }

    // The NewSessionTickets should have been flushed and processed.
    EXPECT_TRUE(g_last_session);
  }
}

TEST(SSLTest, AddChainCertHack) {
  // Ensure that we don't accidently break the hack that we have in place to
  // keep curl and serf happy when they use an |X509| even after transfering
  // ownership.

  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  X509 *cert = GetTestCertificate().release();
  ASSERT_TRUE(cert);
  SSL_CTX_add0_chain_cert(ctx.get(), cert);

  // This should not trigger a use-after-free.
  X509_cmp(cert, cert);
}

TEST(SSLTest, GetCertificate) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  bssl::UniquePtr<X509> cert = GetTestCertificate();
  ASSERT_TRUE(cert);
  ASSERT_TRUE(SSL_CTX_use_certificate(ctx.get(), cert.get()));
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);

  X509 *cert2 = SSL_CTX_get0_certificate(ctx.get());
  ASSERT_TRUE(cert2);

  X509 *cert3 = SSL_get_certificate(ssl.get());
  ASSERT_TRUE(cert3);

  // The old and new certificates must be identical.
  EXPECT_EQ(0, X509_cmp(cert.get(), cert2));
  EXPECT_EQ(0, X509_cmp(cert.get(), cert3));

  uint8_t *der = nullptr;
  long der_len = i2d_X509(cert.get(), &der);
  ASSERT_LT(0, der_len);
  bssl::UniquePtr<uint8_t> free_der(der);

  uint8_t *der2 = nullptr;
  long der2_len = i2d_X509(cert2, &der2);
  ASSERT_LT(0, der2_len);
  bssl::UniquePtr<uint8_t> free_der2(der2);

  uint8_t *der3 = nullptr;
  long der3_len = i2d_X509(cert3, &der3);
  ASSERT_LT(0, der3_len);
  bssl::UniquePtr<uint8_t> free_der3(der3);

  // They must also encode identically.
  EXPECT_EQ(Bytes(der, der_len), Bytes(der2, der2_len));
  EXPECT_EQ(Bytes(der, der_len), Bytes(der3, der3_len));
}

TEST(SSLTest, GetCertificateExData) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  bssl::UniquePtr<X509> cert = GetTestCertificate();
  ASSERT_TRUE(cert);

  int ex_data_index =
      X509_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  const char ex_data[] = "AWS-LC external data";
  ASSERT_TRUE(X509_set_ex_data(cert.get(), ex_data_index, (void *)ex_data));
  ASSERT_TRUE(X509_get_ex_data(cert.get(), ex_data_index));

  ASSERT_TRUE(SSL_CTX_use_certificate(ctx.get(), cert.get()));
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);

  X509 *cert2 = SSL_CTX_get0_certificate(ctx.get());
  ASSERT_TRUE(cert2);
  const char *ex_data2 = (const char *)X509_get_ex_data(cert2, ex_data_index);
  EXPECT_TRUE(ex_data2);

  X509 *cert3 = SSL_get_certificate(ssl.get());
  ASSERT_TRUE(cert3);
  const char *ex_data3 = (const char *)X509_get_ex_data(cert3, ex_data_index);
  EXPECT_TRUE(ex_data3);

  // The external data extracted must be identical.
  EXPECT_EQ(ex_data2, ex_data);
  EXPECT_EQ(ex_data3, ex_data);
}

TEST(SSLTest, GetCertificateASN1) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  bssl::UniquePtr<X509> cert = GetTestCertificate();
  ASSERT_TRUE(cert);

  // Convert cert to ASN1 to pass in.
  uint8_t *der = nullptr;
  size_t der_len = i2d_X509(cert.get(), &der);
  bssl::UniquePtr<uint8_t> free_der(der);

  ASSERT_TRUE(SSL_CTX_use_certificate_ASN1(ctx.get(), der_len, der));
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);

  X509 *cert2 = SSL_CTX_get0_certificate(ctx.get());
  ASSERT_TRUE(cert2);

  X509 *cert3 = SSL_get_certificate(ssl.get());
  ASSERT_TRUE(cert3);

  // The old and new certificates must be identical.
  EXPECT_EQ(0, X509_cmp(cert.get(), cert2));
  EXPECT_EQ(0, X509_cmp(cert.get(), cert3));

  uint8_t *der2 = nullptr;
  long der2_len = i2d_X509(cert2, &der2);
  ASSERT_LT(0, der2_len);
  bssl::UniquePtr<uint8_t> free_der2(der2);

  uint8_t *der3 = nullptr;
  long der3_len = i2d_X509(cert3, &der3);
  ASSERT_LT(0, der3_len);
  bssl::UniquePtr<uint8_t> free_der3(der3);

  // They must also encode identically.
  EXPECT_EQ(Bytes(der, der_len), Bytes(der2, der2_len));
  EXPECT_EQ(Bytes(der, der_len), Bytes(der3, der3_len));
}

TEST(SSLTest, SetChainAndKeyMismatch) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_with_buffers_method()));
  ASSERT_TRUE(ctx);

  bssl::UniquePtr<EVP_PKEY> key = GetTestKey();
  ASSERT_TRUE(key);
  bssl::UniquePtr<CRYPTO_BUFFER> leaf = GetChainTestCertificateBuffer();
  ASSERT_TRUE(leaf);
  std::vector<CRYPTO_BUFFER *> chain = {
      leaf.get(),
  };

  // Should fail because |GetTestKey| doesn't match the chain-test certificate.
  ASSERT_FALSE(SSL_CTX_set_chain_and_key(ctx.get(), &chain[0], chain.size(),
                                         key.get(), nullptr));
  ERR_clear_error();

  // Ensure |SSL_CTX_use_cert_and_key| also fails
  bssl::UniquePtr<X509> x509_leaf = X509FromBuffer(GetChainTestCertificateBuffer());
  ASSERT_FALSE(SSL_CTX_use_cert_and_key(ctx.get(), x509_leaf.get(),
                                        key.get(), NULL, 1));
  ERR_clear_error();
}

TEST(SSLTest, SetChainAndKey) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_with_buffers_method()));
  ASSERT_TRUE(client_ctx);
  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_with_buffers_method()));
  ASSERT_TRUE(server_ctx);

  ASSERT_EQ(nullptr, SSL_CTX_get0_chain(server_ctx.get()));

  bssl::UniquePtr<EVP_PKEY> key = GetChainTestKey();
  ASSERT_TRUE(key);
  bssl::UniquePtr<CRYPTO_BUFFER> leaf = GetChainTestCertificateBuffer();
  ASSERT_TRUE(leaf);
  bssl::UniquePtr<CRYPTO_BUFFER> intermediate =
      GetChainTestIntermediateBuffer();
  ASSERT_TRUE(intermediate);
  std::vector<CRYPTO_BUFFER *> chain = {
      leaf.get(),
      intermediate.get(),
  };
  ASSERT_TRUE(SSL_CTX_set_chain_and_key(server_ctx.get(), &chain[0],
                                        chain.size(), key.get(), nullptr));

  ASSERT_EQ(chain.size(),
            sk_CRYPTO_BUFFER_num(SSL_CTX_get0_chain(server_ctx.get())));

  SSL_CTX_set_custom_verify(
      client_ctx.get(), SSL_VERIFY_PEER,
      [](SSL *ssl, uint8_t *out_alert) -> ssl_verify_result_t {
        return ssl_verify_ok;
      });

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));
}

TEST(SSLTest, SetLeafChainAndKey) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(client_ctx);
  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(server_ctx);

  ASSERT_EQ(nullptr, SSL_CTX_get0_chain(server_ctx.get()));

  bssl::UniquePtr<EVP_PKEY> key = GetChainTestKey();
  ASSERT_TRUE(key);
  bssl::UniquePtr<X509> leaf = GetChainTestCertificate();
  ASSERT_TRUE(leaf);
  bssl::UniquePtr<X509> intermediate = GetChainTestIntermediate();
  bssl::UniquePtr<STACK_OF(X509)> chain(sk_X509_new_null());
  ASSERT_TRUE(chain);
  ASSERT_TRUE(PushToStack(chain.get(), std::move(intermediate)));

  ASSERT_TRUE(SSL_CTX_use_cert_and_key(server_ctx.get(), leaf.get(),
                                        key.get(), chain.get(), 1));

  SSL_CTX_set_custom_verify(
      client_ctx.get(), SSL_VERIFY_PEER,
      [](SSL *ssl, uint8_t *out_alert) -> ssl_verify_result_t {
        return ssl_verify_ok;
      });

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));

  // Try setting on previously populated fields without an override
  ASSERT_FALSE(SSL_CTX_use_cert_and_key(server_ctx.get(), leaf.get(),
                                        key.get(), chain.get(), 0));
  ERR_clear_error();
}

TEST(SSLTest, BuffersFailWithoutCustomVerify) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_with_buffers_method()));
  ASSERT_TRUE(client_ctx);
  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_with_buffers_method()));
  ASSERT_TRUE(server_ctx);

  bssl::UniquePtr<EVP_PKEY> key = GetChainTestKey();
  ASSERT_TRUE(key);
  bssl::UniquePtr<CRYPTO_BUFFER> leaf = GetChainTestCertificateBuffer();
  ASSERT_TRUE(leaf);
  std::vector<CRYPTO_BUFFER *> chain = {leaf.get()};
  ASSERT_TRUE(SSL_CTX_set_chain_and_key(server_ctx.get(), &chain[0],
                                        chain.size(), key.get(), nullptr));

  // Without SSL_CTX_set_custom_verify(), i.e. with everything in the default
  // configuration, certificate verification should fail.
  bssl::UniquePtr<SSL> client, server;
  ASSERT_FALSE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                      server_ctx.get()));

  // Whereas with a verifier, the connection should succeed.
  SSL_CTX_set_custom_verify(
      client_ctx.get(), SSL_VERIFY_PEER,
      [](SSL *ssl, uint8_t *out_alert) -> ssl_verify_result_t {
        return ssl_verify_ok;
      });
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));
}

TEST(SSLTest, CustomVerify) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_with_buffers_method()));
  ASSERT_TRUE(client_ctx);
  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_with_buffers_method()));
  ASSERT_TRUE(server_ctx);

  bssl::UniquePtr<EVP_PKEY> key = GetChainTestKey();
  ASSERT_TRUE(key);
  bssl::UniquePtr<CRYPTO_BUFFER> leaf = GetChainTestCertificateBuffer();
  ASSERT_TRUE(leaf);
  std::vector<CRYPTO_BUFFER *> chain = {leaf.get()};
  ASSERT_TRUE(SSL_CTX_set_chain_and_key(server_ctx.get(), &chain[0],
                                        chain.size(), key.get(), nullptr));

  SSL_CTX_set_custom_verify(
      client_ctx.get(), SSL_VERIFY_PEER,
      [](SSL *ssl, uint8_t *out_alert) -> ssl_verify_result_t {
        return ssl_verify_ok;
      });

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));

  // With SSL_VERIFY_PEER, ssl_verify_invalid should result in a dropped
  // connection.
  SSL_CTX_set_custom_verify(
      client_ctx.get(), SSL_VERIFY_PEER,
      [](SSL *ssl, uint8_t *out_alert) -> ssl_verify_result_t {
        return ssl_verify_invalid;
      });

  ASSERT_FALSE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                      server_ctx.get()));

  // But with SSL_VERIFY_NONE, ssl_verify_invalid should not cause a dropped
  // connection.
  SSL_CTX_set_custom_verify(
      client_ctx.get(), SSL_VERIFY_NONE,
      [](SSL *ssl, uint8_t *out_alert) -> ssl_verify_result_t {
        return ssl_verify_invalid;
      });

  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));
}

TEST(SSLTest, ClientCABuffers) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_with_buffers_method()));
  ASSERT_TRUE(client_ctx);
  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_with_buffers_method()));
  ASSERT_TRUE(server_ctx);

  bssl::UniquePtr<EVP_PKEY> key = GetChainTestKey();
  ASSERT_TRUE(key);
  bssl::UniquePtr<CRYPTO_BUFFER> leaf = GetChainTestCertificateBuffer();
  ASSERT_TRUE(leaf);
  bssl::UniquePtr<CRYPTO_BUFFER> intermediate =
      GetChainTestIntermediateBuffer();
  ASSERT_TRUE(intermediate);
  std::vector<CRYPTO_BUFFER *> chain = {
      leaf.get(),
      intermediate.get(),
  };
  ASSERT_TRUE(SSL_CTX_set_chain_and_key(server_ctx.get(), &chain[0],
                                        chain.size(), key.get(), nullptr));

  bssl::UniquePtr<CRYPTO_BUFFER> ca_name(
      CRYPTO_BUFFER_new(kTestName, sizeof(kTestName), nullptr));
  ASSERT_TRUE(ca_name);
  bssl::UniquePtr<STACK_OF(CRYPTO_BUFFER)> ca_names(
      sk_CRYPTO_BUFFER_new_null());
  ASSERT_TRUE(ca_names);
  ASSERT_TRUE(PushToStack(ca_names.get(), std::move(ca_name)));
  SSL_CTX_set0_client_CAs(server_ctx.get(), ca_names.release());

  // Configure client and server to accept all certificates.
  SSL_CTX_set_custom_verify(
      client_ctx.get(), SSL_VERIFY_PEER,
      [](SSL *ssl, uint8_t *out_alert) -> ssl_verify_result_t {
        return ssl_verify_ok;
      });
  SSL_CTX_set_custom_verify(
      server_ctx.get(), SSL_VERIFY_PEER,
      [](SSL *ssl, uint8_t *out_alert) -> ssl_verify_result_t {
        return ssl_verify_ok;
      });

  bool cert_cb_called = false;
  SSL_CTX_set_cert_cb(
      client_ctx.get(),
      [](SSL *ssl, void *arg) -> int {
        const STACK_OF(CRYPTO_BUFFER) *peer_names =
            SSL_get0_server_requested_CAs(ssl);
        EXPECT_EQ(1u, sk_CRYPTO_BUFFER_num(peer_names));
        CRYPTO_BUFFER *peer_name = sk_CRYPTO_BUFFER_value(peer_names, 0);
        EXPECT_EQ(Bytes(kTestName), Bytes(CRYPTO_BUFFER_data(peer_name),
                                          CRYPTO_BUFFER_len(peer_name)));
        *reinterpret_cast<bool *>(arg) = true;
        return 1;
      },
      &cert_cb_called);

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));
  EXPECT_TRUE(cert_cb_called);
}

// Configuring the empty cipher list, though an error, should still modify the
// configuration.
TEST(SSLTest, EmptyCipherList) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);

  // Initially, the cipher list is not empty.
  EXPECT_NE(0u, sk_SSL_CIPHER_num(SSL_CTX_get_ciphers(ctx.get())));

  // Configuring the empty cipher list with |SSL_CTX_set_cipher_list|
  // succeeds.
  EXPECT_TRUE(SSL_CTX_set_cipher_list(ctx.get(), ""));
  // The cipher list should only be populated with default TLS 1.3 ciphersuites
  EXPECT_EQ(3u, sk_SSL_CIPHER_num(SSL_CTX_get_ciphers(ctx.get())));

  // Configuring the empty cipher list with |SSL_CTX_set_ciphersuites| works
  EXPECT_TRUE(SSL_CTX_set_ciphersuites(ctx.get(), ""));
  EXPECT_EQ(0u, sk_SSL_CIPHER_num(ctx->tls13_cipher_list->ciphers.get()));
  EXPECT_EQ(0u, sk_SSL_CIPHER_num(SSL_CTX_get_ciphers(ctx.get())));

  // Configuring the empty cipher list with |SSL_CTX_set_strict_cipher_list|
  // fails.
  EXPECT_FALSE(SSL_CTX_set_strict_cipher_list(ctx.get(), ""));
  ERR_clear_error();

  // But the cipher list is still updated to empty.
  EXPECT_EQ(0u, sk_SSL_CIPHER_num(SSL_CTX_get_ciphers(ctx.get())));
}

struct TLSVersionTestParams {
  uint16_t version;
};

const TLSVersionTestParams kTLSVersionTests[] = {
    {TLS1_VERSION},
    {TLS1_1_VERSION},
    {TLS1_2_VERSION},
    {TLS1_3_VERSION},
};

struct CertificateKeyTestParams {
  bssl::UniquePtr<X509> (*certificate)();
  bssl::UniquePtr<EVP_PKEY> (*key)();
  int slot_index;
  const char suite[50];
  uint16_t corresponding_sigalg;
};

const CertificateKeyTestParams kCertificateKeyTests[] = {
    {GetTestCertificate, GetTestKey, SSL_PKEY_RSA,
     "TLS_RSA_WITH_AES_256_CBC_SHA:", SSL_SIGN_RSA_PSS_RSAE_SHA256},
    {GetECDSATestCertificate, GetECDSATestKey, SSL_PKEY_ECC,
     "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:",
     SSL_SIGN_ECDSA_SECP256R1_SHA256},
    {GetED25519TestCertificate, GetED25519TestKey, SSL_PKEY_ED25519,
     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:", SSL_SIGN_ED25519},
};

class MultipleCertificateSlotTest
    : public testing::TestWithParam<
          std::tuple<TLSVersionTestParams, CertificateKeyTestParams>> {
 public:
  MultipleCertificateSlotTest() {
    this->version = version_param().version;
    this->slot_index = certificate_key_param().slot_index;
  }

  uint16_t version = 0;
  int slot_index = -1;

  static TLSVersionTestParams version_param() {
    return std::get<0>(GetParam());
  }
  static CertificateKeyTestParams certificate_key_param() {
    return std::get<1>(GetParam());
  }

  const void StandardCertificateSlotIndexTests(SSL_CTX *client_ctx,
                                               SSL_CTX *server_ctx,
                                               std::vector<uint16_t> sigalgs,
                                               int last_cert_type_set,
                                               int should_connect) {
    EXPECT_TRUE(SSL_CTX_set_signing_algorithm_prefs(client_ctx, sigalgs.data(),
                                                    sigalgs.size()));
    EXPECT_TRUE(SSL_CTX_set_verify_algorithm_prefs(client_ctx, sigalgs.data(),
                                                   sigalgs.size()));

    ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx, version));
    ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx, version));
    ASSERT_TRUE(SSL_CTX_set_min_proto_version(server_ctx, version));
    ASSERT_TRUE(SSL_CTX_set_max_proto_version(server_ctx, version));

    ClientConfig config;
    bssl::UniquePtr<SSL> client, server;

    EXPECT_EQ(ConnectClientAndServer(&client, &server, client_ctx, server_ctx,
                                     config, false),
              should_connect);
    if (!should_connect) {
      return;
    }

    ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));

    // Check the internal slot index to verify that the correct slot was set.
    // This should be the slot of the last certificate that was set in
    // |server_ctx|.
    EXPECT_EQ(server_ctx->cert->cert_private_key_idx, last_cert_type_set);
    EXPECT_EQ(server->ctx->cert->cert_private_key_idx, last_cert_type_set);

    // Check the internal slot index to verify that the correct slot was used
    // during the handshake.
    EXPECT_EQ(server->config->cert->cert_private_key_idx, slot_index);
  }
};

INSTANTIATE_TEST_SUITE_P(
    MultipleCertificateSlotAllTest, MultipleCertificateSlotTest,
    testing::Combine(testing::ValuesIn(kTLSVersionTests),
                     testing::ValuesIn(kCertificateKeyTests)));

// Sets up the |SSL_CTX| with |SSL_CTX_use_certificate| & |SSL_use_PrivateKey|.
TEST_P(MultipleCertificateSlotTest, CertificateSlotIndex) {
  if (version < TLS1_2_VERSION && slot_index == SSL_PKEY_ED25519) {
    // ED25519 is not supported in versions prior to TLS1.2.
    GTEST_SKIP();
  }
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx(CreateContextWithCertificate(
      TLS_method(), certificate_key_param().certificate(),
      certificate_key_param().key()));

  StandardCertificateSlotIndexTests(
      client_ctx.get(), server_ctx.get(),
      {SSL_SIGN_ED25519, SSL_SIGN_ECDSA_SECP256R1_SHA256,
       SSL_SIGN_RSA_PSS_RSAE_SHA256},
      slot_index, true);
}

// Sets up the |SSL_CTX| with |SSL_CTX_set_chain_and_key|.
TEST_P(MultipleCertificateSlotTest, SetChainAndKeyIndex) {
  if (version < TLS1_2_VERSION && slot_index == SSL_PKEY_ED25519) {
    // ED25519 is not supported in versions prior to TLS1.2.
    GTEST_SKIP();
  }
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_method()));

  uint8_t *buf = nullptr;
  int cert_len = i2d_X509(certificate_key_param().certificate().get(), &buf);
  bssl::UniquePtr<uint8_t> free_buf(buf);

  bssl::UniquePtr<CRYPTO_BUFFER> leaf(
      CRYPTO_BUFFER_new(buf, cert_len, nullptr));
  ASSERT_TRUE(leaf);
  std::vector<CRYPTO_BUFFER *> chain = {leaf.get()};

  ASSERT_TRUE(
      SSL_CTX_set_chain_and_key(server_ctx.get(), &chain[0], chain.size(),
                                certificate_key_param().key().get(), nullptr));

  StandardCertificateSlotIndexTests(
      client_ctx.get(), server_ctx.get(),
      {SSL_SIGN_ED25519, SSL_SIGN_ECDSA_SECP256R1_SHA256,
       SSL_SIGN_RSA_PSS_RSAE_SHA256},
      slot_index, true);
}

TEST_P(MultipleCertificateSlotTest, AutomaticSelectionSigAlgs) {
  if (version < TLS1_2_VERSION && slot_index == SSL_PKEY_ED25519) {
    // ED25519 is not supported in versions prior to TLS1.2.
    GTEST_SKIP();
  }

  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_method()));

  ASSERT_TRUE(
      SSL_CTX_use_certificate(server_ctx.get(), GetTestCertificate().get()));
  ASSERT_TRUE(SSL_CTX_use_PrivateKey(server_ctx.get(), GetTestKey().get()));
  ASSERT_TRUE(SSL_CTX_use_certificate(server_ctx.get(),
                                      GetECDSATestCertificate().get()));
  ASSERT_TRUE(
      SSL_CTX_use_PrivateKey(server_ctx.get(), GetECDSATestKey().get()));
  ASSERT_TRUE(SSL_CTX_use_certificate(server_ctx.get(),
                                      GetED25519TestCertificate().get()));
  ASSERT_TRUE(
      SSL_CTX_use_PrivateKey(server_ctx.get(), GetED25519TestKey().get()));


  // Versions prior to TLS1.3 need a valid authentication cipher suite to pair
  // with the certificate.
  if (version < TLS1_3_VERSION) {
    ASSERT_TRUE(SSL_CTX_set_cipher_list(client_ctx.get(),
                                        certificate_key_param().suite));
  }

  StandardCertificateSlotIndexTests(
      client_ctx.get(), server_ctx.get(),
      {certificate_key_param().corresponding_sigalg}, SSL_PKEY_ED25519, true);
}

TEST_P(MultipleCertificateSlotTest, AutomaticSelectionCipherAuth) {
  if ((version < TLS1_2_VERSION && slot_index == SSL_PKEY_ED25519) ||
      version >= TLS1_3_VERSION) {
    // ED25519 is not supported in versions prior to TLS1.2.
    // TLS 1.3 not have cipher-based authentication configuration.
    GTEST_SKIP();
  }

  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_method()));

  ASSERT_TRUE(
      SSL_CTX_use_certificate(server_ctx.get(), GetTestCertificate().get()));
  ASSERT_TRUE(SSL_CTX_use_PrivateKey(server_ctx.get(), GetTestKey().get()));
  ASSERT_TRUE(SSL_CTX_use_certificate(server_ctx.get(),
                                      GetECDSATestCertificate().get()));
  ASSERT_TRUE(
      SSL_CTX_use_PrivateKey(server_ctx.get(), GetECDSATestKey().get()));
  ASSERT_TRUE(SSL_CTX_use_certificate(server_ctx.get(),
                                      GetED25519TestCertificate().get()));
  ASSERT_TRUE(
      SSL_CTX_use_PrivateKey(server_ctx.get(), GetED25519TestKey().get()));


  // Versions prior to TLS1.3 need a valid authentication cipher suite to pair
  // with the certificate.
  if (version < TLS1_3_VERSION) {
    ASSERT_TRUE(SSL_CTX_set_cipher_list(client_ctx.get(),
                                        certificate_key_param().suite));
  }

  // We allow all possible sigalgs in this test, but either the ECDSA or ED25519
  // certificate could be chosen when using an |SSL_aECDSA| ciphersuite.
  std::vector<uint16_t> sigalgs = {SSL_SIGN_RSA_PSS_RSAE_SHA256};
  if (slot_index == SSL_PKEY_ED25519) {
    sigalgs.push_back(SSL_SIGN_ED25519);
  } else {
    sigalgs.push_back(SSL_SIGN_ECDSA_SECP256R1_SHA256);
  }

  StandardCertificateSlotIndexTests(client_ctx.get(), server_ctx.get(), sigalgs,
                                    SSL_PKEY_ED25519, true);
}

TEST_P(MultipleCertificateSlotTest, MissingCertificate) {
  if (version < TLS1_2_VERSION && slot_index == SSL_PKEY_ED25519) {
    // ED25519 is not supported in versions prior to TLS1.2.
    GTEST_SKIP();
  }

  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_method()));

  ASSERT_TRUE(SSL_CTX_use_PrivateKey(server_ctx.get(), GetTestKey().get()));
  ASSERT_TRUE(
      SSL_CTX_use_PrivateKey(server_ctx.get(), GetECDSATestKey().get()));
  ASSERT_TRUE(
      SSL_CTX_use_PrivateKey(server_ctx.get(), GetED25519TestKey().get()));

  // Versions prior to TLS1.3 need a valid authentication cipher suite to pair
  // with the certificate.
  if (version < TLS1_3_VERSION) {
    ASSERT_TRUE(SSL_CTX_set_cipher_list(client_ctx.get(),
                                        certificate_key_param().suite));
  }

  StandardCertificateSlotIndexTests(
      client_ctx.get(), server_ctx.get(),
      {certificate_key_param().corresponding_sigalg}, -1, false);
}

TEST_P(MultipleCertificateSlotTest, MissingPrivateKey) {
  if (version < TLS1_2_VERSION && slot_index == SSL_PKEY_ED25519) {
    // ED25519 is not supported in versions prior to TLS1.2.
    GTEST_SKIP();
  }

  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_method()));

  ASSERT_TRUE(
      SSL_CTX_use_certificate(server_ctx.get(), GetTestCertificate().get()));
  ASSERT_TRUE(SSL_CTX_use_certificate(server_ctx.get(),
                                      GetECDSATestCertificate().get()));
  ASSERT_TRUE(SSL_CTX_use_certificate(server_ctx.get(),
                                      GetED25519TestCertificate().get()));

  // Versions prior to TLS1.3 need a valid authentication cipher suite to pair
  // with the certificate.
  if (version < TLS1_3_VERSION) {
    ASSERT_TRUE(SSL_CTX_set_cipher_list(client_ctx.get(),
                                        certificate_key_param().suite));
  }

  StandardCertificateSlotIndexTests(
      client_ctx.get(), server_ctx.get(),
      {certificate_key_param().corresponding_sigalg}, -1, false);
}


struct MultiTransferReadWriteTestParams {
  const char suite[50];
  bool tls13;
  bssl::UniquePtr<X509> (*certificate)();
  bssl::UniquePtr<EVP_PKEY> (*key)();
};

static const MultiTransferReadWriteTestParams kMultiTransferReadWriteTests[] = {
    {"TLS_AES_128_GCM_SHA256:", true, GetECDSATestCertificate, GetECDSATestKey},
    {"TLS_AES_256_GCM_SHA384:", true, GetECDSATestCertificate, GetECDSATestKey},
    {"TLS_CHACHA20_POLY1305_SHA256:", true, GetECDSATestCertificate,
     GetECDSATestKey},
    {"TLS_RSA_WITH_NULL_SHA:", false, GetTestCertificate, GetTestKey},
    {"TLS_RSA_WITH_3DES_EDE_CBC_SHA:", false, GetTestCertificate, GetTestKey},
    {"TLS_RSA_WITH_AES_128_CBC_SHA:", false, GetTestCertificate, GetTestKey},
    {"TLS_RSA_WITH_AES_256_CBC_SHA:", false, GetTestCertificate, GetTestKey},
    {"TLS_RSA_WITH_AES_128_CBC_SHA256:", false, GetTestCertificate, GetTestKey},
    {"TLS_RSA_WITH_AES_128_GCM_SHA256:", false, GetTestCertificate, GetTestKey},
    {"TLS_RSA_WITH_AES_256_GCM_SHA384:", false, GetTestCertificate, GetTestKey},
    {"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:", false, GetECDSATestCertificate,
     GetECDSATestKey},
    {"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:", false, GetECDSATestCertificate,
     GetECDSATestKey},
    {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:", false, GetTestCertificate,
     GetTestKey},
    {"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:", false, GetTestCertificate,
     GetTestKey},
    {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:", false, GetTestCertificate,
     GetTestKey},
    {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:", false, GetECDSATestCertificate,
     GetECDSATestKey},
    {"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:", false, GetECDSATestCertificate,
     GetECDSATestKey},
    {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:", false, GetTestCertificate,
     GetTestKey},
    {"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:", false, GetTestCertificate,
     GetTestKey},
    {"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:", false, GetTestCertificate,
     GetTestKey},
    {"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:", false,
     GetECDSATestCertificate, GetECDSATestKey}};

class MultiTransferReadWriteTest
    : public testing::TestWithParam<MultiTransferReadWriteTestParams> {};

INSTANTIATE_TEST_SUITE_P(SuiteTests, MultiTransferReadWriteTest,
                         testing::ValuesIn(kMultiTransferReadWriteTests));

TEST_P(MultiTransferReadWriteTest, SuiteTransfers) {
  auto params = GetParam();

  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx(CreateContextWithCertificate(
      TLS_method(), params.certificate(), params.key()));

  uint16_t version = TLS1_2_VERSION;
  int (*set_cipher_suites)(SSL_CTX *, const char *) = SSL_CTX_set_cipher_list;
  if (params.tls13) {
    version = TLS1_3_VERSION;
    set_cipher_suites = SSL_CTX_set_ciphersuites;
  }

  ASSERT_TRUE(set_cipher_suites(client_ctx.get(), params.suite));
  ASSERT_TRUE(set_cipher_suites(server_ctx.get(), params.suite));

  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), version));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), version));
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(server_ctx.get(), version));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(server_ctx.get(), version));

  ClientConfig config;
  bssl::UniquePtr<SSL> client, server;

  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get(), config, true));

  ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));

  bssl::UniquePtr<SSL> transfer_server;
  TransferSSL(&server, server_ctx.get(), &transfer_server);
  server = std::move(transfer_server);

  char buf[3];
  size_t buf_cap = sizeof(buf);

  for (size_t t = 0; t < 5; t++) {
    for (size_t i = 0; i < 20; i++) {
      std::string send_str = std::to_string(i);

      // Assert server open
      ASSERT_TRUE(SSL_write(client.get(), send_str.c_str(), send_str.length()));
      int read = SSL_read(server.get(), buf, buf_cap);
      ASSERT_TRUE(read);
      ASSERT_TRUE((size_t)read == send_str.length());
      std::string read_str(buf, read);
      ASSERT_EQ(send_str, read_str);

      // Assert server seal
      ASSERT_TRUE(SSL_write(server.get(), send_str.c_str(), send_str.length()));
      read = SSL_read(client.get(), buf, buf_cap);
      ASSERT_TRUE(read);
      ASSERT_TRUE((size_t)read == send_str.length());
      read_str = std::string(buf, read);
      ASSERT_EQ(send_str, read_str);
    }
    TransferSSL(&server, server_ctx.get(), &transfer_server);
    server = std::move(transfer_server);
  }
}

// ssl_test_ticket_aead_failure_mode enumerates the possible ways in which the
// test |SSL_TICKET_AEAD_METHOD| can fail.
enum ssl_test_ticket_aead_failure_mode {
  ssl_test_ticket_aead_ok = 0,
  ssl_test_ticket_aead_seal_fail,
  ssl_test_ticket_aead_open_soft_fail,
  ssl_test_ticket_aead_open_hard_fail,
};

struct ssl_test_ticket_aead_state {
  unsigned retry_count = 0;
  ssl_test_ticket_aead_failure_mode failure_mode = ssl_test_ticket_aead_ok;
};

static int ssl_test_ticket_aead_ex_index_dup(CRYPTO_EX_DATA *to,
                                             const CRYPTO_EX_DATA *from,
                                             void **from_d, int index,
                                             long argl, void *argp) {
  abort();
}

static void ssl_test_ticket_aead_ex_index_free(void *parent, void *ptr,
                                               CRYPTO_EX_DATA *ad, int index,
                                               long argl, void *argp) {
  delete reinterpret_cast<ssl_test_ticket_aead_state*>(ptr);
}

static CRYPTO_once_t g_ssl_test_ticket_aead_ex_index_once = CRYPTO_ONCE_INIT;
static int g_ssl_test_ticket_aead_ex_index;

static int ssl_test_ticket_aead_get_ex_index() {
  CRYPTO_once(&g_ssl_test_ticket_aead_ex_index_once, [] {
    g_ssl_test_ticket_aead_ex_index = SSL_get_ex_new_index(
        0, nullptr, nullptr, ssl_test_ticket_aead_ex_index_dup,
        ssl_test_ticket_aead_ex_index_free);
  });
  return g_ssl_test_ticket_aead_ex_index;
}

static size_t ssl_test_ticket_aead_max_overhead(SSL *ssl) { return 1; }

static int ssl_test_ticket_aead_seal(SSL *ssl, uint8_t *out, size_t *out_len,
                                     size_t max_out_len, const uint8_t *in,
                                     size_t in_len) {
  auto state = reinterpret_cast<ssl_test_ticket_aead_state *>(
      SSL_get_ex_data(ssl, ssl_test_ticket_aead_get_ex_index()));

  if (state->failure_mode == ssl_test_ticket_aead_seal_fail ||
      max_out_len < in_len + 1) {
    return 0;
  }

  OPENSSL_memmove(out, in, in_len);
  out[in_len] = 0xff;
  *out_len = in_len + 1;

  return 1;
}

static ssl_ticket_aead_result_t ssl_test_ticket_aead_open(
    SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out_len,
    const uint8_t *in, size_t in_len) {
  auto state = reinterpret_cast<ssl_test_ticket_aead_state *>(
      SSL_get_ex_data(ssl, ssl_test_ticket_aead_get_ex_index()));

  if (state->retry_count > 0) {
    state->retry_count--;
    return ssl_ticket_aead_retry;
  }

  switch (state->failure_mode) {
    case ssl_test_ticket_aead_ok:
      break;
    case ssl_test_ticket_aead_seal_fail:
      // If |seal| failed then there shouldn't be any ticket to try and
      // decrypt.
      abort();
      break;
    case ssl_test_ticket_aead_open_soft_fail:
      return ssl_ticket_aead_ignore_ticket;
    case ssl_test_ticket_aead_open_hard_fail:
      return ssl_ticket_aead_error;
  }

  if (in_len == 0 || in[in_len - 1] != 0xff) {
    return ssl_ticket_aead_ignore_ticket;
  }

  if (max_out_len < in_len - 1) {
    return ssl_ticket_aead_error;
  }

  OPENSSL_memmove(out, in, in_len - 1);
  *out_len = in_len - 1;
  return ssl_ticket_aead_success;
}

static const SSL_TICKET_AEAD_METHOD kSSLTestTicketMethod = {
    ssl_test_ticket_aead_max_overhead,
    ssl_test_ticket_aead_seal,
    ssl_test_ticket_aead_open,
};

static void ConnectClientAndServerWithTicketMethod(
    bssl::UniquePtr<SSL> *out_client, bssl::UniquePtr<SSL> *out_server,
    SSL_CTX *client_ctx, SSL_CTX *server_ctx, unsigned retry_count,
    ssl_test_ticket_aead_failure_mode failure_mode, SSL_SESSION *session) {
  bssl::UniquePtr<SSL> client(SSL_new(client_ctx)), server(SSL_new(server_ctx));
  ASSERT_TRUE(client);
  ASSERT_TRUE(server);
  SSL_set_connect_state(client.get());
  SSL_set_accept_state(server.get());

  auto state = new ssl_test_ticket_aead_state;
  state->retry_count = retry_count;
  state->failure_mode = failure_mode;

  ASSERT_GE(ssl_test_ticket_aead_get_ex_index(), 0);
  ASSERT_TRUE(SSL_set_ex_data(server.get(), ssl_test_ticket_aead_get_ex_index(),
                              state));

  SSL_set_session(client.get(), session);

  BIO *bio1, *bio2;
  ASSERT_TRUE(BIO_new_bio_pair(&bio1, 0, &bio2, 0));

  // SSL_set_bio takes ownership.
  SSL_set_bio(client.get(), bio1, bio1);
  SSL_set_bio(server.get(), bio2, bio2);

  if (CompleteHandshakes(client.get(), server.get())) {
    *out_client = std::move(client);
    *out_server = std::move(server);
  } else {
    out_client->reset();
    out_server->reset();
  }
}

using TicketAEADMethodParam =
    testing::tuple<uint16_t, unsigned, ssl_test_ticket_aead_failure_mode, bool>;

class TicketAEADMethodTest
    : public ::testing::TestWithParam<TicketAEADMethodParam> {};

TEST_P(TicketAEADMethodTest, Resume) {
  bssl::UniquePtr<SSL_CTX> server_ctx =
      CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(server_ctx);
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(client_ctx);

  const uint16_t version = testing::get<0>(GetParam());
  const unsigned retry_count = testing::get<1>(GetParam());
  const ssl_test_ticket_aead_failure_mode failure_mode =
      testing::get<2>(GetParam());
  const bool transfer_ssl = testing::get<3>(GetParam());

  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), version));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), version));
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(server_ctx.get(), version));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(server_ctx.get(), version));

  SSL_CTX_set_session_cache_mode(client_ctx.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_current_time_cb(client_ctx.get(), FrozenTimeCallback);
  SSL_CTX_set_current_time_cb(server_ctx.get(), FrozenTimeCallback);
  SSL_CTX_sess_set_new_cb(client_ctx.get(), SaveLastSession);

  SSL_CTX_set_ticket_aead_method(server_ctx.get(), &kSSLTestTicketMethod);

  bssl::UniquePtr<SSL> client, server;
  ASSERT_NO_FATAL_FAILURE(ConnectClientAndServerWithTicketMethod(
      &client, &server, client_ctx.get(), server_ctx.get(), retry_count,
      failure_mode, nullptr));
  // Only transfer when the code is to test SSL transfer and the connection is
  // finished successuflly.
  if (transfer_ssl && server) {
    // |server| is reset to hold the transferred SSL.
    TransferSSL(&server, server_ctx.get(), nullptr);
  }
  switch (failure_mode) {
    case ssl_test_ticket_aead_ok:
    case ssl_test_ticket_aead_open_hard_fail:
    case ssl_test_ticket_aead_open_soft_fail:
      ASSERT_TRUE(client);
      break;
    case ssl_test_ticket_aead_seal_fail:
      EXPECT_FALSE(client);
      return;
  }
  EXPECT_FALSE(SSL_session_reused(client.get()));
  EXPECT_FALSE(SSL_session_reused(server.get()));

  ASSERT_TRUE(FlushNewSessionTickets(client.get(), server.get()));
  bssl::UniquePtr<SSL_SESSION> session = std::move(g_last_session);
  ASSERT_NO_FATAL_FAILURE(ConnectClientAndServerWithTicketMethod(
      &client, &server, client_ctx.get(), server_ctx.get(), retry_count,
      failure_mode, session.get()));
  // Do SSL transfer again.
  // Only transfer when the code is to test SSL transfer and the connection is
  // finished successuflly.
  if (transfer_ssl && server) {
    // |server| is reset to hold the transferred SSL.
    TransferSSL(&server, server_ctx.get(), nullptr);
  }
  switch (failure_mode) {
    case ssl_test_ticket_aead_ok:
      ASSERT_TRUE(client);
      EXPECT_TRUE(SSL_session_reused(client.get()));
      EXPECT_TRUE(SSL_session_reused(server.get()));
      break;
    case ssl_test_ticket_aead_seal_fail:
      abort();
      break;
    case ssl_test_ticket_aead_open_hard_fail:
      EXPECT_FALSE(client);
      break;
    case ssl_test_ticket_aead_open_soft_fail:
      ASSERT_TRUE(client);
      EXPECT_FALSE(SSL_session_reused(client.get()));
      EXPECT_FALSE(SSL_session_reused(server.get()));
  }
}

std::string TicketAEADMethodParamToString(
    const testing::TestParamInfo<TicketAEADMethodParam> &params) {
  std::string ret = GetVersionName(std::get<0>(params.param));
  // GTest only allows alphanumeric characters and '_' in the parameter
  // string. Additionally filter out the 'v' to get "TLS13" over "TLSv13".
  for (auto it = ret.begin(); it != ret.end();) {
    if (*it == '.' || *it == 'v') {
      it = ret.erase(it);
    } else {
      ++it;
    }
  }
  char retry_count[256];
  snprintf(retry_count, sizeof(retry_count), "%u", std::get<1>(params.param));
  ret += "_";
  ret += retry_count;
  ret += "Retries_";
  switch (std::get<2>(params.param)) {
    case ssl_test_ticket_aead_ok:
      ret += "OK";
      break;
    case ssl_test_ticket_aead_seal_fail:
      ret += "SealFail";
      break;
    case ssl_test_ticket_aead_open_soft_fail:
      ret += "OpenSoftFail";
      break;
    case ssl_test_ticket_aead_open_hard_fail:
      ret += "OpenHardFail";
      break;
  }
  if (std::get<3>(params.param)) {
    ret += "_SSLTransfer";
  }
  return ret;
}

INSTANTIATE_TEST_SUITE_P(
    TicketAEADMethodTests, TicketAEADMethodTest,
    testing::Combine(testing::Values(TLS1_2_VERSION, TLS1_3_VERSION),
                     testing::Values(0, 1, 2),
                     testing::Values(ssl_test_ticket_aead_ok,
                                     ssl_test_ticket_aead_seal_fail,
                                     ssl_test_ticket_aead_open_soft_fail,
                                     ssl_test_ticket_aead_open_hard_fail),
                     testing::Values(TRANSFER_SSL, !TRANSFER_SSL)),
    TicketAEADMethodParamToString);

TEST(SSLTest, SelectNextProto) {
  uint8_t *result;
  uint8_t result_len;

  // If there is an overlap, it should be returned.
  EXPECT_EQ(OPENSSL_NPN_NEGOTIATED,
            SSL_select_next_proto(&result, &result_len,
                                  (const uint8_t *)"\1a\2bb\3ccc", 9,
                                  (const uint8_t *)"\1x\1y\1a\1z", 8));
  EXPECT_EQ(Bytes("a"), Bytes(result, result_len));

  EXPECT_EQ(OPENSSL_NPN_NEGOTIATED,
            SSL_select_next_proto(&result, &result_len,
                                  (const uint8_t *)"\1a\2bb\3ccc", 9,
                                  (const uint8_t *)"\1x\1y\2bb\1z", 9));
  EXPECT_EQ(Bytes("bb"), Bytes(result, result_len));

  EXPECT_EQ(OPENSSL_NPN_NEGOTIATED,
            SSL_select_next_proto(&result, &result_len,
                                  (const uint8_t *)"\1a\2bb\3ccc", 9,
                                  (const uint8_t *)"\1x\1y\3ccc\1z", 10));
  EXPECT_EQ(Bytes("ccc"), Bytes(result, result_len));

  // Peer preference order takes precedence over local.
  EXPECT_EQ(OPENSSL_NPN_NEGOTIATED,
            SSL_select_next_proto(&result, &result_len,
                                  (const uint8_t *)"\1a\2bb\3ccc", 9,
                                  (const uint8_t *)"\3ccc\2bb\1a", 9));
  EXPECT_EQ(Bytes("a"), Bytes(result, result_len));

  // If there is no overlap, opportunistically select the first local protocol.
  // ALPN callers should ignore this, but NPN callers may use this per
  // draft-agl-tls-nextprotoneg-03, section 6.
  EXPECT_EQ(OPENSSL_NPN_NO_OVERLAP,
            SSL_select_next_proto(&result, &result_len,
                                  (const uint8_t *)"\1a\2bb\3ccc", 9,
                                  (const uint8_t *)"\1x\2yy\3zzz", 9));
  EXPECT_EQ(Bytes("x"), Bytes(result, result_len));

  // The peer preference order may be empty in NPN. This should be treated as no
  // overlap and continue to select an opportunistic protocol.
  EXPECT_EQ(OPENSSL_NPN_NO_OVERLAP,
            SSL_select_next_proto(&result, &result_len, nullptr, 0,
                                  (const uint8_t *)"\1x\2yy\3zzz", 9));
  EXPECT_EQ(Bytes("x"), Bytes(result, result_len));

  // Although calling this function with no local protocols is a caller error,
  // it should cleanly return an empty protocol.
  EXPECT_EQ(
      OPENSSL_NPN_NO_OVERLAP,
      SSL_select_next_proto(&result, &result_len,
                            (const uint8_t *)"\1a\2bb\3ccc", 9, nullptr, 0));
  EXPECT_EQ(Bytes(""), Bytes(result, result_len));

  // Syntax errors are similarly caller errors.
  EXPECT_EQ(
      OPENSSL_NPN_NO_OVERLAP,
      SSL_select_next_proto(&result, &result_len, (const uint8_t *)"\4aaa", 4,
                            (const uint8_t *)"\1a\2bb\3ccc", 9));
  EXPECT_EQ(Bytes(""), Bytes(result, result_len));
  EXPECT_EQ(OPENSSL_NPN_NO_OVERLAP,
            SSL_select_next_proto(&result, &result_len,
                                  (const uint8_t *)"\1a\2bb\3ccc", 9,
                                  (const uint8_t *)"\4aaa", 4));
  EXPECT_EQ(Bytes(""), Bytes(result, result_len));

  // Protocols in protocol lists may not be empty.
  EXPECT_EQ(OPENSSL_NPN_NO_OVERLAP,
            SSL_select_next_proto(&result, &result_len,
                                  (const uint8_t *)"\0\2bb\3ccc", 8,
                                  (const uint8_t *)"\1a\2bb\3ccc", 9));
  EXPECT_EQ(OPENSSL_NPN_NO_OVERLAP,
            SSL_select_next_proto(&result, &result_len,
                                  (const uint8_t *)"\1a\2bb\3ccc", 9,
                                  (const uint8_t *)"\0\2bb\3ccc", 8));
  EXPECT_EQ(Bytes(""), Bytes(result, result_len));
}

// The client should gracefully handle no suitable ciphers being enabled.
TEST(SSLTest, NoCiphersAvailable) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);

  // Configure |client_ctx| with a cipher list that does not intersect with its
  // version configuration.
  ASSERT_TRUE(SSL_CTX_set_strict_cipher_list(
      ctx.get(), "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(ctx.get(), TLS1_1_VERSION));

  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);
  SSL_set_connect_state(ssl.get());

  UniquePtr<BIO> rbio(BIO_new(BIO_s_mem())), wbio(BIO_new(BIO_s_mem()));
  ASSERT_TRUE(rbio);
  ASSERT_TRUE(wbio);
  SSL_set0_rbio(ssl.get(), rbio.release());
  SSL_set0_wbio(ssl.get(), wbio.release());

  int ret = SSL_do_handshake(ssl.get());
  EXPECT_EQ(-1, ret);
  EXPECT_EQ(SSL_ERROR_SSL, SSL_get_error(ssl.get(), ret));
  EXPECT_TRUE(
      ErrorEquals(ERR_get_error(), ERR_LIB_SSL, SSL_R_NO_CIPHERS_AVAILABLE));
}

TEST_P(SSLVersionTest, SessionVersion) {
  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx_.get(), SSL_SESS_CACHE_BOTH);

  bssl::UniquePtr<SSL_SESSION> session =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());
  ASSERT_TRUE(session);
  EXPECT_EQ(version(), SSL_SESSION_get_protocol_version(session.get()));

  // Sessions in TLS 1.3 and later should be single-use.
  EXPECT_EQ(version() == TLS1_3_VERSION,
            !!SSL_SESSION_should_be_single_use(session.get()));

  // Making fake sessions for testing works.
  session.reset(SSL_SESSION_new(client_ctx_.get()));
  ASSERT_TRUE(session);
  ASSERT_TRUE(SSL_SESSION_set_protocol_version(session.get(), version()));
  EXPECT_EQ(version(), SSL_SESSION_get_protocol_version(session.get()));
}

TEST_P(SSLVersionTest, SSLPending) {
  UniquePtr<SSL> ssl(SSL_new(client_ctx_.get()));
  ASSERT_TRUE(ssl);
  EXPECT_EQ(0, SSL_pending(ssl.get()));

  ASSERT_TRUE(Connect());
  EXPECT_EQ(0, SSL_pending(client_.get()));
  EXPECT_EQ(0, SSL_has_pending(client_.get()));

  ASSERT_EQ(5, SSL_write(server_.get(), "hello", 5));
  ASSERT_EQ(5, SSL_write(server_.get(), "world", 5));
  EXPECT_EQ(0, SSL_pending(client_.get()));
  EXPECT_EQ(0, SSL_has_pending(client_.get()));

  char buf[10];
  ASSERT_EQ(1, SSL_peek(client_.get(), buf, 1));
  EXPECT_EQ(5, SSL_pending(client_.get()));
  EXPECT_EQ(1, SSL_has_pending(client_.get()));

  ASSERT_EQ(1, SSL_read(client_.get(), buf, 1));
  EXPECT_EQ(4, SSL_pending(client_.get()));
  EXPECT_EQ(1, SSL_has_pending(client_.get()));

  ASSERT_EQ(4, SSL_read(client_.get(), buf, 10));
  EXPECT_EQ(0, SSL_pending(client_.get()));
  if (is_dtls()) {
    // In DTLS, the two records would have been read as a single datagram and
    // buffered inside |client_|. Thus, |SSL_has_pending| should return true.
    //
    // This test is slightly unrealistic. It relies on |ConnectClientAndServer|
    // using a |BIO| pair, which does not preserve datagram boundaries. Reading
    // 1 byte, then 4 bytes, from the first record also relies on
    // https://crbug.com/boringssl/65. But it does test the codepaths. When
    // fixing either of these bugs, this test may need to be redone.
    EXPECT_EQ(1, SSL_has_pending(client_.get()));
  } else {
    // In TLS if read ahead is enabled the two records would also have been read
    // in a single call.
    EXPECT_EQ(enable_read_ahead(), SSL_has_pending(client_.get()));
  }

  ASSERT_EQ(2, SSL_read(client_.get(), buf, 2));
  EXPECT_EQ(3, SSL_pending(client_.get()));
  EXPECT_EQ(1, SSL_has_pending(client_.get()));
}

// Identical test to the |SSLPending| test suite above, but with
// |SSL_(read/peek/write)_ex| operations instead.
TEST_P(SSLVersionTest, SSLPendingEx) {
  UniquePtr<SSL> ssl(SSL_new(client_ctx_.get()));
  ASSERT_TRUE(ssl);
  EXPECT_EQ(0, SSL_pending(ssl.get()));

  ASSERT_TRUE(Connect());
  EXPECT_EQ(0, SSL_pending(client_.get()));
  EXPECT_EQ(0, SSL_has_pending(client_.get()));

  size_t buf_len;
  ASSERT_EQ(1, SSL_write_ex(server_.get(), "hello", 5, &buf_len));
  ASSERT_EQ(buf_len, (size_t)5);
  ASSERT_EQ(1, SSL_write_ex(server_.get(), "world", 5, &buf_len));
  ASSERT_EQ(buf_len, (size_t)5);

  EXPECT_EQ(0, SSL_pending(client_.get()));
  EXPECT_EQ(0, SSL_has_pending(client_.get()));

  char buf[10];
  ASSERT_EQ(1, SSL_peek_ex(client_.get(), buf, 1, &buf_len));
  ASSERT_EQ(buf_len, (size_t)1);
  EXPECT_EQ(5, SSL_pending(client_.get()));
  EXPECT_EQ(1, SSL_has_pending(client_.get()));

  ASSERT_EQ(1, SSL_read_ex(client_.get(), buf, 1, &buf_len));
  ASSERT_EQ(buf_len, (size_t)1);
  EXPECT_EQ(4, SSL_pending(client_.get()));
  EXPECT_EQ(1, SSL_has_pending(client_.get()));

  ASSERT_EQ(1, SSL_read_ex(client_.get(), buf, 10, &buf_len));
  ASSERT_EQ(buf_len, (size_t)4);
  EXPECT_EQ(0, SSL_pending(client_.get()));
  if (is_dtls()) {
    EXPECT_EQ(1, SSL_has_pending(client_.get()));
  } else {
    // In TLS if read ahead is enabled the two records would also have been read
    // in a single call.
    EXPECT_EQ(enable_read_ahead(), SSL_has_pending(client_.get()));
  }

  ASSERT_EQ(1, SSL_read_ex(client_.get(), buf, 2, &buf_len));
  ASSERT_EQ(buf_len, (size_t)2);
  EXPECT_EQ(3, SSL_pending(client_.get()));
  EXPECT_EQ(1, SSL_has_pending(client_.get()));

  // 0-sized IO with valid inputs should succeed but not read/write nor effect
  // buffer state. However, NULL |read_bytes|/|written| pointer should fail.
  const int client_pending = SSL_pending(client_.get());
  ASSERT_EQ(1, SSL_read_ex(client_.get(), (void *)"", 0, &buf_len));
  ASSERT_EQ(0UL, buf_len);
  ASSERT_EQ(client_pending, SSL_pending(client_.get()));
  ASSERT_EQ(1, SSL_write_ex(client_.get(), (void *)"", 0, &buf_len));
  ASSERT_EQ(0UL, buf_len);
  ASSERT_EQ(client_pending, SSL_pending(client_.get()));
  ASSERT_EQ(0, SSL_read_ex(client_.get(), (void *)"", 0, nullptr));
  ASSERT_EQ(0, SSL_write_ex(client_.get(), (void *)"", 0, nullptr));
}

TEST_P(SSLVersionTest, ReadAhead) {
  ASSERT_TRUE(Connect());
  size_t buf_len;
  std::string test_string = "Hello, world!";
  for (char & i : test_string) {
    ASSERT_EQ(1, SSL_write_ex(server_.get(), &i, 1, &buf_len));
  }

  char buf[13];
  size_t starting_size = BIO_pending(client_.get()->rbio.get());

  ASSERT_NE(0UL, starting_size);
  ASSERT_EQ(1, SSL_read_ex(client_.get(), buf, 1, &buf_len));
  if (enable_read_ahead() || is_dtls()) {
    // Even though we didn't request the full string (13 * record overhead)
    // everything should be read from the BIO
    if (read_ahead_buffer_size() > starting_size || is_dtls()) {
      ASSERT_EQ(0UL, BIO_pending(client_.get()->rbio.get()));
    } else {
      // Depending on TLS version each record will be a different size and a
      // variable but non-zero amount of data will remain
      ASSERT_NE(0UL, BIO_pending(client_.get()->rbio.get()));
    }
  } else {
    // Only the requested 1 byte + TLS record overhead should have been read,
    // the remaining 12 letters each in its own record should be in the BIO
    // not the SSLBuffer
    ASSERT_NE(0UL, BIO_pending(client_.get()->rbio.get()));
  }
}

// Test that post-handshake tickets consumed by |SSL_shutdown| are ignored.
TEST(SSLTest, ShutdownIgnoresTickets) {
  bssl::UniquePtr<SSL_CTX> ctx(CreateContextWithTestCertificate(TLS_method()));
  ASSERT_TRUE(ctx);
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION));

  SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_BOTH);

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, ctx.get(), ctx.get()));

  SSL_CTX_sess_set_new_cb(ctx.get(), [](SSL *ssl, SSL_SESSION *session) -> int {
    ADD_FAILURE() << "New session callback called during SSL_shutdown";
    return 0;
  });

  // Send close_notify.
  EXPECT_EQ(0, SSL_shutdown(server.get()));
  EXPECT_EQ(0, SSL_shutdown(client.get()));

  // Receive close_notify.
  EXPECT_EQ(1, SSL_shutdown(server.get()));
  EXPECT_EQ(1, SSL_shutdown(client.get()));
}

TEST(SSLTest, SignatureAlgorithmProperties) {
  EXPECT_EQ(EVP_PKEY_NONE, SSL_get_signature_algorithm_key_type(0x1234));
  EXPECT_EQ(nullptr, SSL_get_signature_algorithm_digest(0x1234));
  EXPECT_FALSE(SSL_is_signature_algorithm_rsa_pss(0x1234));

  EXPECT_EQ(EVP_PKEY_RSA,
            SSL_get_signature_algorithm_key_type(SSL_SIGN_RSA_PKCS1_MD5_SHA1));
  EXPECT_EQ(EVP_md5_sha1(),
            SSL_get_signature_algorithm_digest(SSL_SIGN_RSA_PKCS1_MD5_SHA1));
  EXPECT_FALSE(SSL_is_signature_algorithm_rsa_pss(SSL_SIGN_RSA_PKCS1_MD5_SHA1));

  EXPECT_EQ(EVP_PKEY_EC, SSL_get_signature_algorithm_key_type(
                             SSL_SIGN_ECDSA_SECP256R1_SHA256));
  EXPECT_EQ(EVP_sha256(), SSL_get_signature_algorithm_digest(
                              SSL_SIGN_ECDSA_SECP256R1_SHA256));
  EXPECT_FALSE(
      SSL_is_signature_algorithm_rsa_pss(SSL_SIGN_ECDSA_SECP256R1_SHA256));

  EXPECT_EQ(EVP_PKEY_RSA,
            SSL_get_signature_algorithm_key_type(SSL_SIGN_RSA_PSS_RSAE_SHA384));
  EXPECT_EQ(EVP_sha384(),
            SSL_get_signature_algorithm_digest(SSL_SIGN_RSA_PSS_RSAE_SHA384));
  EXPECT_TRUE(SSL_is_signature_algorithm_rsa_pss(SSL_SIGN_RSA_PSS_RSAE_SHA384));
}

static int XORCompressFunc(SSL *ssl, CBB *out, const uint8_t *in,
                           size_t in_len) {
  for (size_t i = 0; i < in_len; i++) {
    if (!CBB_add_u8(out, in[i] ^ 0x55)) {
      return 0;
    }
  }

  SSL_set_app_data(ssl, XORCompressFunc);

  return 1;
}

static int XORDecompressFunc(SSL *ssl, CRYPTO_BUFFER **out,
                             size_t uncompressed_len, const uint8_t *in,
                             size_t in_len) {
  if (in_len != uncompressed_len) {
    return 0;
  }

  uint8_t *data;
  *out = CRYPTO_BUFFER_alloc(&data, uncompressed_len);
  if (*out == nullptr) {
    return 0;
  }

  for (size_t i = 0; i < in_len; i++) {
    data[i] = in[i] ^ 0x55;
  }

  SSL_set_app_data(ssl, XORDecompressFunc);

  return 1;
}

TEST(SSLTest, CertCompression) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx(
      CreateContextWithTestCertificate(TLS_method()));
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_add_cert_compression_alg(
      client_ctx.get(), 0x1234, XORCompressFunc, XORDecompressFunc));
  ASSERT_TRUE(SSL_CTX_add_cert_compression_alg(
      server_ctx.get(), 0x1234, XORCompressFunc, XORDecompressFunc));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));

  EXPECT_TRUE(SSL_get_app_data(client.get()) == XORDecompressFunc);
  EXPECT_TRUE(SSL_get_app_data(server.get()) == XORCompressFunc);
}

void MoveBIOs(SSL *dest, SSL *src) {
  BIO *rbio = SSL_get_rbio(src);
  BIO_up_ref(rbio);
  SSL_set0_rbio(dest, rbio);

  BIO *wbio = SSL_get_wbio(src);
  BIO_up_ref(wbio);
  SSL_set0_wbio(dest, wbio);

  SSL_set0_rbio(src, nullptr);
  SSL_set0_wbio(src, nullptr);
}

void VerifyHandoff(bool use_new_alps_codepoint) {
  static const uint8_t alpn[] = {0x03, 'f', 'o', 'o'};
  static const uint8_t proto[] = {'f', 'o', 'o'};
  static const uint8_t alps[] = {0x04, 'a', 'l', 'p', 's'};

  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> handshaker_ctx(
      CreateContextWithTestCertificate(TLS_method()));
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  ASSERT_TRUE(handshaker_ctx);

  if (!use_new_alps_codepoint) {
    SetUpExpectedOldCodePoint(server_ctx.get());
  } else {
    SetUpExpectedNewCodePoint(server_ctx.get());
  }

  SSL_CTX_set_session_cache_mode(client_ctx.get(), SSL_SESS_CACHE_CLIENT);
  SSL_CTX_sess_set_new_cb(client_ctx.get(), SaveLastSession);
  SSL_CTX_set_handoff_mode(server_ctx.get(), true);
  uint8_t keys[48];
  SSL_CTX_get_tlsext_ticket_keys(server_ctx.get(), &keys, sizeof(keys));
  SSL_CTX_set_tlsext_ticket_keys(handshaker_ctx.get(), &keys, sizeof(keys));

  for (bool early_data : {false, true}) {
    SCOPED_TRACE(early_data);
    for (bool is_resume : {false, true}) {
      SCOPED_TRACE(is_resume);
      bssl::UniquePtr<SSL> client, server;
      ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(),
                                        server_ctx.get()));
      SSL_set_early_data_enabled(client.get(), early_data);

      // Set up client ALPS settings.
      SSL_set_alps_use_new_codepoint(client.get(), use_new_alps_codepoint);
      ASSERT_TRUE(SSL_set_alpn_protos(client.get(), alpn, sizeof(alpn)) == 0);
      ASSERT_TRUE(SSL_add_application_settings(client.get(), proto,
                                              sizeof(proto), nullptr, 0));
      if (is_resume) {
        ASSERT_TRUE(g_last_session);
        SSL_set_session(client.get(), g_last_session.get());
        if (early_data) {
          EXPECT_GT(g_last_session->ticket_max_early_data, 0u);
        }
      }


      int client_ret = SSL_do_handshake(client.get());
      int client_err = SSL_get_error(client.get(), client_ret);

      uint8_t byte_written;
      if (early_data && is_resume) {
        ASSERT_EQ(client_err, 0);
        EXPECT_TRUE(SSL_in_early_data(client.get()));
        // Attempt to write early data.
        byte_written = 43;
        EXPECT_EQ(SSL_write(client.get(), &byte_written, 1), 1);
      } else {
        ASSERT_EQ(client_err, SSL_ERROR_WANT_READ);
      }

      int server_ret = SSL_do_handshake(server.get());
      int server_err = SSL_get_error(server.get(), server_ret);
      ASSERT_EQ(server_err, SSL_ERROR_HANDOFF);

      ScopedCBB cbb;
      Array<uint8_t> handoff;
      SSL_CLIENT_HELLO hello;
      ASSERT_TRUE(CBB_init(cbb.get(), 256));
      ASSERT_TRUE(SSL_serialize_handoff(server.get(), cbb.get(), &hello));
      ASSERT_TRUE(CBBFinishArray(cbb.get(), &handoff));

      bssl::UniquePtr<SSL> handshaker(SSL_new(handshaker_ctx.get()));
      ASSERT_TRUE(handshaker);
      // Note split handshakes determines 0-RTT support, for both the current
      // handshake and newly-issued tickets, entirely by |handshaker|. There is
      // no need to call |SSL_set_early_data_enabled| on |server|.
      SSL_set_early_data_enabled(handshaker.get(), 1);

      // Set up handshaker ALPS settings.
      SSL_set_alps_use_new_codepoint(handshaker.get(), use_new_alps_codepoint);
      SSL_CTX_set_alpn_select_cb(
          handshaker_ctx.get(),
          [](SSL *ssl, const uint8_t **out, uint8_t *out_len, const uint8_t *in,
              unsigned in_len, void *arg) -> int {
            return SSL_select_next_proto(
                        const_cast<uint8_t **>(out), out_len, in, in_len,
                        alpn, sizeof(alpn)) == OPENSSL_NPN_NEGOTIATED
                        ? SSL_TLSEXT_ERR_OK
                        : SSL_TLSEXT_ERR_NOACK;
          },
          nullptr);
      ASSERT_TRUE(SSL_add_application_settings(handshaker.get(), proto,
                                              sizeof(proto), alps, sizeof(alps)));

      ASSERT_TRUE(SSL_apply_handoff(handshaker.get(), handoff));

      MoveBIOs(handshaker.get(), server.get());

      int handshake_ret = SSL_do_handshake(handshaker.get());
      int handshake_err = SSL_get_error(handshaker.get(), handshake_ret);
      ASSERT_EQ(handshake_err, SSL_ERROR_HANDBACK);

      // Double-check that additional calls to |SSL_do_handshake| continue
      // to get |SSL_ERROR_HANDBACK|.
      handshake_ret = SSL_do_handshake(handshaker.get());
      handshake_err = SSL_get_error(handshaker.get(), handshake_ret);
      ASSERT_EQ(handshake_err, SSL_ERROR_HANDBACK);

      ScopedCBB cbb_handback;
      Array<uint8_t> handback;
      ASSERT_TRUE(CBB_init(cbb_handback.get(), 1024));
      ASSERT_TRUE(SSL_serialize_handback(handshaker.get(), cbb_handback.get()));
      ASSERT_TRUE(CBBFinishArray(cbb_handback.get(), &handback));

      bssl::UniquePtr<SSL> server2(SSL_new(server_ctx.get()));
      ASSERT_TRUE(server2);
      ASSERT_TRUE(SSL_apply_handback(server2.get(), handback));

      MoveBIOs(server2.get(), handshaker.get());
      ASSERT_TRUE(CompleteHandshakes(client.get(), server2.get()));
      EXPECT_EQ(is_resume, SSL_session_reused(client.get()));
      // Verify application settings.
      ASSERT_TRUE(SSL_has_application_settings(client.get()));

      if (early_data && is_resume) {
        // In this case, one byte of early data has already been written above.
        EXPECT_TRUE(SSL_early_data_accepted(client.get()));
      } else {
        byte_written = 42;
        EXPECT_EQ(SSL_write(client.get(), &byte_written, 1), 1);
      }
      uint8_t byte;
      EXPECT_EQ(SSL_read(server2.get(), &byte, 1), 1);
      EXPECT_EQ(byte_written, byte);

      byte = 44;
      EXPECT_EQ(SSL_write(server2.get(), &byte, 1), 1);
      EXPECT_EQ(SSL_read(client.get(), &byte, 1), 1);
      EXPECT_EQ(44, byte);
    }
  }
}

TEST(SSLTest, Handoff) {
  for (bool use_new_alps_codepoint : {false, true}) {
    SCOPED_TRACE(use_new_alps_codepoint);
    VerifyHandoff(use_new_alps_codepoint);
  }
}

TEST(SSLTest, HandoffDeclined) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx(
      CreateContextWithTestCertificate(TLS_method()));
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  SSL_CTX_set_handoff_mode(server_ctx.get(), true);
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_2_VERSION));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(),
                                    server_ctx.get()));

  int client_ret = SSL_do_handshake(client.get());
  int client_err = SSL_get_error(client.get(), client_ret);
  ASSERT_EQ(client_err, SSL_ERROR_WANT_READ);

  int server_ret = SSL_do_handshake(server.get());
  int server_err = SSL_get_error(server.get(), server_ret);
  ASSERT_EQ(server_err, SSL_ERROR_HANDOFF);

  ScopedCBB cbb;
  SSL_CLIENT_HELLO hello;
  ASSERT_TRUE(CBB_init(cbb.get(), 256));
  ASSERT_TRUE(SSL_serialize_handoff(server.get(), cbb.get(), &hello));

  ASSERT_TRUE(SSL_decline_handoff(server.get()));

  ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));

  uint8_t byte = 42;
  EXPECT_EQ(SSL_write(client.get(), &byte, 1), 1);
  EXPECT_EQ(SSL_read(server.get(), &byte, 1), 1);
  EXPECT_EQ(42, byte);

  byte = 43;
  EXPECT_EQ(SSL_write(server.get(), &byte, 1), 1);
  EXPECT_EQ(SSL_read(client.get(), &byte, 1), 1);
  EXPECT_EQ(43, byte);
}

static std::string SigAlgsToString(Span<const uint16_t> sigalgs) {
  std::string ret = "{";

  for (uint16_t v : sigalgs) {
    if (ret.size() > 1) {
      ret += ", ";
    }

    char buf[8];
    snprintf(buf, sizeof(buf) - 1, "0x%02x", v);
    buf[sizeof(buf) - 1] = 0;
    ret += std::string(buf);
  }

  ret += "}";
  return ret;
}

void ExpectSigAlgsEqual(Span<const uint16_t> expected,
                        Span<const uint16_t> actual) {
  bool matches = false;
  if (expected.size() == actual.size()) {
    matches = true;

    for (size_t i = 0; i < expected.size(); i++) {
      if (expected[i] != actual[i]) {
        matches = false;
        break;
      }
    }
  }

  if (!matches) {
    ADD_FAILURE() << "expected: " << SigAlgsToString(expected)
                  << " got: " << SigAlgsToString(actual);
  }
}

TEST(SSLTest, SigAlgs) {
  static const struct {
    std::vector<int> input;
    bool ok;
    std::vector<uint16_t> expected;
  } kTests[] = {
      {{}, true, {}},
      {{1}, false, {}},
      {{1, 2, 3}, false, {}},
      {{NID_sha256, EVP_PKEY_ED25519}, false, {}},
      {{NID_sha256, EVP_PKEY_RSA, NID_sha256, EVP_PKEY_RSA}, false, {}},

      {{NID_sha256, EVP_PKEY_RSA}, true, {SSL_SIGN_RSA_PKCS1_SHA256}},
      {{NID_sha512, EVP_PKEY_RSA}, true, {SSL_SIGN_RSA_PKCS1_SHA512}},
      {{NID_sha256, EVP_PKEY_RSA_PSS}, true, {SSL_SIGN_RSA_PSS_RSAE_SHA256}},
      {{NID_undef, EVP_PKEY_ED25519}, true, {SSL_SIGN_ED25519}},
      {{NID_undef, EVP_PKEY_ED25519, NID_sha384, EVP_PKEY_EC},
       true,
       {SSL_SIGN_ED25519, SSL_SIGN_ECDSA_SECP384R1_SHA384}},
  };

  UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);

  unsigned n = 1;
  for (const auto &test : kTests) {
    SCOPED_TRACE(n++);

    const bool ok =
        SSL_CTX_set1_sigalgs(ctx.get(), test.input.data(), test.input.size());
    EXPECT_EQ(ok, test.ok);

    if (!ok) {
      ERR_clear_error();
    }

    if (!test.ok) {
      continue;
    }

    ExpectSigAlgsEqual(test.expected, ctx->cert->sigalgs);
  }
}

TEST(SSLTest, SigAlgsList) {
  static const struct {
    const char *input;
    bool ok;
    std::vector<uint16_t> expected;
  } kTests[] = {
      {"", false, {}},
      {":", false, {}},
      {"+", false, {}},
      {"RSA", false, {}},
      {"RSA+", false, {}},
      {"RSA+SHA256:", false, {}},
      {":RSA+SHA256:", false, {}},
      {":RSA+SHA256+:", false, {}},
      {"!", false, {}},
      {"\x01", false, {}},
      {"RSA+SHA256:RSA+SHA384:RSA+SHA256", false, {}},
      {"RSA-PSS+SHA256:rsa_pss_rsae_sha256", false, {}},

      {"RSA+SHA256", true, {SSL_SIGN_RSA_PKCS1_SHA256}},
      {"RSA+SHA256:ed25519",
       true,
       {SSL_SIGN_RSA_PKCS1_SHA256, SSL_SIGN_ED25519}},
      {"ECDSA+SHA256:RSA+SHA512",
       true,
       {SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PKCS1_SHA512}},
      {"ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256",
       true,
       {SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PSS_RSAE_SHA256}},
      {"RSA-PSS+SHA256", true, {SSL_SIGN_RSA_PSS_RSAE_SHA256}},
      {"PSS+SHA256", true, {SSL_SIGN_RSA_PSS_RSAE_SHA256}},
  };

  UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);

  unsigned n = 1;
  for (const auto &test : kTests) {
    SCOPED_TRACE(n++);

    const bool ok = SSL_CTX_set1_sigalgs_list(ctx.get(), test.input);
    EXPECT_EQ(ok, test.ok);

    if (!ok) {
      if (test.ok) {
        ERR_print_errors_fp(stderr);
      }
      ERR_clear_error();
    }

    if (!test.ok) {
      continue;
    }

    ExpectSigAlgsEqual(test.expected, ctx->cert->sigalgs);
  }
}

TEST(SSLTest, DISABLED_ApplyHandoffRemovesUnsupportedCiphers) {
  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(server_ctx);
  bssl::UniquePtr<SSL> server(SSL_new(server_ctx.get()));
  ASSERT_TRUE(server);

  // handoff is a handoff message that has been artificially modified to pretend
  // that only cipher 0x0A is supported.  When it is applied to |server|, all
  // ciphers but that one should be removed.
  //
  // To make a new one of these, try sticking this in the |Handoff| test above:
  //
  // hexdump(stderr, "", handoff.data(), handoff.size());
  // sed -e 's/\(..\)/0x\1, /g'
  //
  // and modify serialize_features() to emit only cipher 0x0A.

  uint8_t handoff[] = {
      0x30, 0x81, 0x9a, 0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x81, 0x82, 0x01,
      0x00, 0x00, 0x7e, 0x03, 0x03, 0x30, 0x8e, 0x8f, 0x79, 0xd2, 0x87, 0x39,
      0xc2, 0x23, 0x23, 0x13, 0xca, 0x3c, 0x80, 0x44, 0xfd, 0x80, 0x83, 0x62,
      0x3c, 0xcc, 0xf8, 0x76, 0xd3, 0x62, 0xbb, 0x54, 0xe3, 0xc4, 0x39, 0x24,
      0xa5, 0x00, 0x00, 0x1e, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
      0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x0a, 0xc0, 0x14,
      0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, 0x01, 0x00,
      0x00, 0x37, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
      0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
      0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0d, 0x00,
      0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08,
      0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x04, 0x02, 0x00,
      0x0a, 0x04, 0x0a, 0x00, 0x15, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00,
      0x1d,
  };

  EXPECT_EQ(22u, sk_SSL_CIPHER_num(SSL_get_ciphers(server.get())));
  ASSERT_TRUE(
      SSL_apply_handoff(server.get(), {handoff, OPENSSL_ARRAY_SIZE(handoff)}));
  EXPECT_EQ(1u, sk_SSL_CIPHER_num(SSL_get_ciphers(server.get())));
}

TEST(SSLTest, ApplyHandoffRemovesUnsupportedCurves) {
  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(server_ctx);
  bssl::UniquePtr<SSL> server(SSL_new(server_ctx.get()));
  ASSERT_TRUE(server);

  // handoff is a handoff message that has been artificially modified to pretend
  // that only one ECDH group is supported.  When it is applied to |server|, all
  // groups but that one should be removed.
  //
  // See |ApplyHandoffRemovesUnsupportedCiphers| for how to make a new one of
  // these.
  uint8_t handoff[] = {
      0x30, 0x81, 0xc0, 0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x81, 0x82, 0x01,
      0x00, 0x00, 0x7e, 0x03, 0x03, 0x98, 0x30, 0xce, 0xd9, 0xb0, 0xdf, 0x5f,
      0x82, 0x05, 0x4a, 0x43, 0x67, 0x7e, 0xdb, 0x6a, 0x4f, 0x21, 0x18, 0x4e,
      0x0d, 0x94, 0x63, 0x18, 0x8b, 0x54, 0x89, 0xdb, 0x8b, 0x1d, 0x84, 0xbc,
      0x09, 0x00, 0x00, 0x1e, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
      0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x0a, 0xc0, 0x14,
      0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, 0x01, 0x00,
      0x00, 0x37, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
      0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
      0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0d, 0x00,
      0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08,
      0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x04, 0x30, 0x00,
      0x02, 0x00, 0x0a, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x8c, 0x00, 0x8d, 0x00,
      0x9c, 0x00, 0x9d, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x09, 0xc0,
      0x0a, 0xc0, 0x13, 0xc0, 0x14, 0xc0, 0x2b, 0xc0, 0x2c, 0xc0, 0x2f, 0xc0,
      0x30, 0xc0, 0x35, 0xc0, 0x36, 0xcc, 0xa8, 0xcc, 0xa9, 0xcc, 0xac, 0x04,
      0x02, 0x00, 0x17,
  };

  // The zero length means that the default list of groups is used.
  EXPECT_EQ(0u, server->config->supported_group_list.size());
  ASSERT_TRUE(
      SSL_apply_handoff(server.get(), {handoff, OPENSSL_ARRAY_SIZE(handoff)}));
  EXPECT_EQ(1u, server->config->supported_group_list.size());
}

struct EncodeDecodeKATTestParam {
  const char *input;
  const char *output;
};

static const EncodeDecodeKATTestParam kEncodeDecodeKATs[] = {
    // V1 input round-trips as V2 output
    {"308201173082011302010102020303020240003081fa0201010408000000000000000104"
     "0800000000000000010420000004d29e62f41ded4bb33d0faa6ffada380e2c489dfbfb44"
     "4f574e475244010420cf3926d1ec5a562a642935a8050222b0aed93ffd9d1cac682274d9"
     "42e99e42a604020000020100020103040cb9b409f5129440622f87f84402010c040c1f49"
     "e2e989c66a263e9c227502010c020100020100020100a05b3059020101020203030402cc"
     "a80400043085668dcf9f0921094ebd7f91bf2a8c60d276e4c279fd85a989402f67868232"
     "4fd8098dc19d900b856d0a77e048e3ced2a104020204d2a20402021c20a4020400b10301"
     "01ffb20302011da206040474657374a7030101ff020108020100a0030101ff",
     "308201803082017c02010102020303020240003082016202010204080000000000000001"
     "040800000000000000010420000004d29e62f41ded4bb33d0faa6ffada380e2c489dfbfb"
     "444f574e475244010420cf3926d1ec5a562a642935a8050222b0aed93ffd9d1cac682274"
     "d942e99e42a6040200000201000201030440b9b409f5129440622f87f84402010c040c1f"
     "49e2e989c66a263e9c227502010c020100020100020100a05b3059020101020203030402"
     "cca80400043085668dcf02010c04401f49e2e989c66a263e9c227502010c020100020100"
     "020100a05b3059020101020203030402cca80400043085668dcf9f0921094ebd7f91bf2a"
     "8c60d276e4c27902010c020100020100020100a05b3059020101020203030402cca80400"
     "043085668dcf9f0921094ebd7f91bf2a8c60d276e4c279fd85a989402f678682324fd809"
     "8dc19d900b856d0a77e048e3ced2a104020204d2a20402021c20a4020400b1030101ffb2"
     "0302011da206040474657374a7030101ff020108020100a0030101ff"},
    // In runner.go, the test case "Basic-Server-TLS-Sync-SSL_Transfer" is used
    // to generate below bytes by adding print statement on the output of
    // |SSL_to_bytes| in bssl_shim.cc.
    // We've bumped the buffer size in the |previous_client/server_finished|
    // fields. This verifies that the original size is parsable and reencoded
    // with the new size.
    {"308201173082011302010102020303020240003081fa0201020408000000000000000104"
     "0800000000000000010420000004d29e62f41ded4bb33d0faa6ffada380e2c489dfbfb44"
     "4f574e475244010420cf3926d1ec5a562a642935a8050222b0aed93ffd9d1cac682274d9"
     "42e99e42a604020000020100020103040cb9b409f5129440622f87f84402010c040c1f49"
     "e2e989c66a263e9c227502010c020100020100020100a05b3059020101020203030402cc"
     "a80400043085668dcf9f0921094ebd7f91bf2a8c60d276e4c279fd85a989402f67868232"
     "4fd8098dc19d900b856d0a77e048e3ced2a104020204d2a20402021c20a4020400b10301"
     "01ffb20302011da206040474657374a7030101ff020108020100a0030101ff",
     "308201803082017c02010102020303020240003082016202010204080000000000000001"
     "040800000000000000010420000004d29e62f41ded4bb33d0faa6ffada380e2c489dfbfb"
     "444f574e475244010420cf3926d1ec5a562a642935a8050222b0aed93ffd9d1cac682274"
     "d942e99e42a6040200000201000201030440b9b409f5129440622f87f84402010c040c1f"
     "49e2e989c66a263e9c227502010c020100020100020100a05b3059020101020203030402"
     "cca80400043085668dcf02010c04401f49e2e989c66a263e9c227502010c020100020100"
     "020100a05b3059020101020203030402cca80400043085668dcf9f0921094ebd7f91bf2a"
     "8c60d276e4c27902010c020100020100020100a05b3059020101020203030402cca80400"
     "043085668dcf9f0921094ebd7f91bf2a8c60d276e4c279fd85a989402f678682324fd809"
     "8dc19d900b856d0a77e048e3ced2a104020204d2a20402021c20a4020400b1030101ffb2"
     "0302011da206040474657374a7030101ff020108020100a0030101ff"},
     // In runner.go, the test case
     // "TLS-TLS13-AES_128_GCM_SHA256-server-SSL_Transfer" is used to generate
     // below bytes by adding print statement on the output of |SSL_to_bytes| in
     // bssl_shim.cc.
     // We've bumped the buffer size in the |previous_client/server_finished|
     // fields. This verifies that the original size is parsable and reencoded
     // with the new size.
    {"308203883082038402010102020304020240003082036a020102040800000000000000000"
      "408000000000000000004206beca5c14aff6b92757545948b883c6c175327814bedcf38a6"
      "b2e4c43bc02d180420a32aee5b7705a19e4bb2b47f4918199c76cee7245f1311bc4ba3888"
      "3d33f236a04020000020100020101040c000000000000000000000000020100040c000000"
      "000000000000000000020100020100020100020100a04e304c02010102020304040213010"
      "40004200b66320d38c8fa1b0dfe9e37fcf2bf0bafb43077fa31ed2f1220dd245cef4c4da1"
      "04020204d2a205020302a300a4020400b20302011db9050203093a80a206040474657374a"
      "b03020100ac03010100ad03010100ae03010100af03020100b032043034c0893be938bade"
      "e7029ca3cfea4c821dde48e03f0d07641cba33b247bc161c0000000000000000000000000"
      "0000000b103020120b232043094b319ed2f41ee11aa73e141a238e5724c04f2aa8298c16b"
      "43c910c40cc98d1500000000000000000000000000000000b303020120b432043015a178c"
      "e69c0110ad36da8d58ca8428d9615ff07fc6a4e1bbab026c1bb0c02180000000000000000"
      "0000000000000000b503020120b88201700482016c040000b20002a30056355452010000a"
      "027abfd1f1aa28cee6e8e2396112e8285f150768898158dbce97a1aef0a63fa6dda1002a4"
      "d75942a3739c11e4b25827f529ab59d22e34e0cf0b59b9336eb60edbb1f686c072ab33c30"
      "e784f876da5b4c7fddd67f4a2ffa995f8c9ccf2128200ae9668d626866b1b7c6bb111867a"
      "87ed2a96122736595374f8fe5343e6ca492b278b67b1571423f2c1bcb673922e9044e9094"
      "9975ff72ab4a0eb659d8de664cac600042a2a0000040000b20002a3009e8c6738010100a0"
      "27abfd1f1aa28cee6e8e2396112e82851f15c84668b2f1d717681d1a3c6d2ea52d3401d31"
      "10a04498246480b96a7e5b3c39ea6cef3a2a86b81896f1621950472d858d18796c97e8320"
      "4daf94c1f30dfe763cd282fbee718a679dca8bff3cc8e11724062232e573bcf0252dc4d39"
      "0baa2b7f49a164b46d2d685e9fe826465cc135130f3e2e47838658af57173f864070fdce2"
      "41be58ecbd60d18128dfa28f4b1a00042a2a0000ba2330210201010204030013013016020"
      "101020117040e300c0201010201000201000101ffbb233021020101020403001301301602"
      "0101020117040e300c0201010201000201000101ff020108020100a0030101ff",
      "308203f0308203ec0201010202030402024000308203d202010204080000000000000000"
      "0408000000000000000004206beca5c14aff6b92757545948b883c6c175327814bedcf38"
      "a6b2e4c43bc02d180420a32aee5b7705a19e4bb2b47f4918199c76cee7245f1311bc4ba3"
      "8883d33f236a040200000201000201010440000000000000000000000000020100040c00"
      "0000000000000000000000020100020100020100020100a04e304c020101020203040402"
      "1301040004200b66320d0201000440000000000000000000000000020100020100020100"
      "020100a04e304c0201010202030404021301040004200b66320d38c8fa1b0dfe9e37fcf2"
      "bf0bafb43077fa020100020100020100020100a04e304c02010102020304040213010400"
      "04200b66320d38c8fa1b0dfe9e37fcf2bf0bafb43077fa31ed2f1220dd245cef4c4da104"
      "020204d2a205020302a300a4020400b20302011db9050203093a80a206040474657374ab"
      "03020100ac03010100ad03010100ae03010100af03020100b032043034c0893be938bade"
      "e7029ca3cfea4c821dde48e03f0d07641cba33b247bc161c000000000000000000000000"
      "00000000b103020120b232043094b319ed2f41ee11aa73e141a238e5724c04f2aa8298c1"
      "6b43c910c40cc98d1500000000000000000000000000000000b303020120b432043015a1"
      "78ce69c0110ad36da8d58ca8428d9615ff07fc6a4e1bbab026c1bb0c0218000000000000"
      "00000000000000000000b503020120b88201700482016c040000b20002a3005635545201"
      "0000a027abfd1f1aa28cee6e8e2396112e8285f150768898158dbce97a1aef0a63fa6dda"
      "1002a4d75942a3739c11e4b25827f529ab59d22e34e0cf0b59b9336eb60edbb1f686c072"
      "ab33c30e784f876da5b4c7fddd67f4a2ffa995f8c9ccf2128200ae9668d626866b1b7c6b"
      "b111867a87ed2a96122736595374f8fe5343e6ca492b278b67b1571423f2c1bcb673922e"
      "9044e90949975ff72ab4a0eb659d8de664cac600042a2a0000040000b20002a3009e8c67"
      "38010100a027abfd1f1aa28cee6e8e2396112e82851f15c84668b2f1d717681d1a3c6d2e"
      "a52d3401d3110a04498246480b96a7e5b3c39ea6cef3a2a86b81896f1621950472d858d1"
      "8796c97e83204daf94c1f30dfe763cd282fbee718a679dca8bff3cc8e11724062232e573"
      "bcf0252dc4d390baa2b7f49a164b46d2d685e9fe826465cc135130f3e2e47838658af571"
      "73f864070fdce241be58ecbd60d18128dfa28f4b1a00042a2a0000ba2330210201010204"
      "030013013016020101020117040e300c0201010201000201000101ffbb23302102010102"
      "04030013013016020101020117040e300c0201010201000201000101ff020108020100a0"
      "030101ff"},
    // In runner.go, the test case
    // "TLS-ECH-Server-Cipher-HKDF-SHA256-AES-256-GCM-SSL_Transfer" is used
    // to generate below bytes by adding print statement on the output of
    // |SSL_to_bytes| in bssl_shim.cc.
    {"308203e3308203df0201010202030402024000308203c502010204080000000000000000"
     "04080000000000000000042028431b914ffdb44ea92ca53d5734976c6a16f141d44f180b"
     "0816a5cb2b8e79030420bdaf544fa82d833d58c92213e44e850cc0b8147699b0b410d4aa"
     "2a277030f3220402000002010002010104409e155007d04cd03cf4d8a95ce244dc978a87"
     "e1808f0f6c6acb51ad7bf8063ae000000000000000000000000000000000000000000000"
     "0000000000000000000002012004406680e8c36429d465ea520ae74a2062a5e07c39f34b"
     "688024ae2edfab2898670700000000000000000000000000000000000000000000000000"
     "00000000000000020120020100020100020100a04e304c02010102020304040213030400"
     "0420df74ecd172087ad53083d505145ec4f6cf0ec5ed64b67ba526d55c918a0f8936a104"
     "020204d2a205020302a300a4020400b20302011db9050203093a80a210040e7365637265"
     "742e6578616d706c65ab03020100ac03010100ad03010100ae03010100af03020100b032"
     "0430c40f9f95646fa700d58934e79c36b84ba3502d33df04248d56cded3444927e300000"
     "0000000000000000000000000000b103020120b23204307a1a99bf276b5e5be57dd68968"
     "411594e77b1a48cf2c03cc5c143985aa40b32e00000000000000000000000000000000b3"
     "03020120b4320430cbf50af88bc5a610910139172a468663675882caacaf176aa961b12a"
     "38a0df2a00000000000000000000000000000000b503020120b703020101b88201700482"
     "016c040000b20002a300bbccf972010000a041e0b13ecd71dfb3d9e3cb451e37cfde8197"
     "3a1b73106b6669b53475781f0203a3f32f45cef7742cf0efb86d850081254f20d3b6bd83"
     "30bc70331464905bcd99383c33e42c7d34bfeb47b387bf43b5c796daa4581f8b0043b7eb"
     "216911f8eebaf1e8bd5d05277943d5a319cc03d9555e414990099f56ee887145f34e8bff"
     "27f06d1865aa64d548a22208318566959a097c080fa3e5e0d4b1d933132ef32929950004"
     "5a5a0000040000b20002a3002ecba343010100a041e0b13ecd71dfb3d9e3cb451e37cfde"
     "289f90201519fb0dff08aa9e14a9f4ee1434edce481e49d22f061529bb4d230258f3dac8"
     "86c2c1100bee2ccc7be889a90b417270c30b3b770558ef6f3c444ddefd08e673f788931d"
     "86542c4a1e7ec44b0957bb315c17851bd8498b1d1131a79e19c66463e0566985ef55deb5"
     "48fe370058ba83566278d01b3a565075b8ef2a82bea17ae95fa91b7b3ffa611a7d8a6331"
     "00045a5a0000ba15301302010102040300130330080201010201050400bb153013020101"
     "02040300130330080201010201050400020108020100a0030101ff", nullptr}
};

class EncodeDecodeKATTest
    : public testing::TestWithParam<EncodeDecodeKATTestParam> {};

INSTANTIATE_TEST_SUITE_P(EncodeAndDecodeKATTests, EncodeDecodeKATTest,
                         testing::ValuesIn(kEncodeDecodeKATs));

TEST_P(EncodeDecodeKATTest, RoundTrips) {
  std::string input(GetParam().input);
  std::string output;
  if (GetParam().output) {
    output = std::string(GetParam().output);
  } else {
    output = std::string(GetParam().input);
  }

  std::vector<uint8_t> input_bytes;
  ASSERT_TRUE(DecodeHex(&input_bytes, input));
  std::vector<uint8_t> output_bytes;
  ASSERT_TRUE(DecodeHex(&output_bytes, output));

  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_method()));
  // Check the bytes are decoded successfully.
  bssl::UniquePtr<SSL> ssl(
      SSL_from_bytes(input_bytes.data(), input_bytes.size(), server_ctx.get()));
  ASSERT_TRUE(ssl);
  // Check the ssl can be encoded successfully.
  size_t encoded_len;
  uint8_t *encoded;
  ASSERT_TRUE(SSL_to_bytes(ssl.get(), &encoded, &encoded_len));
  bssl::UniquePtr<uint8_t> encoded_ptr;
  encoded_ptr.reset(encoded);
  // Check the encoded bytes are the same as the test input.
  ASSERT_EQ(output_bytes.size(), encoded_len);
  ASSERT_EQ(OPENSSL_memcmp(output_bytes.data(), encoded, encoded_len), 0);
}

TEST(SSLTest, ZeroSizedWriteFlushesHandshakeMessages) {
  // If there are pending handshake messages, an |SSL_write| of zero bytes
  // should flush them.
  bssl::UniquePtr<SSL_CTX> server_ctx(
      CreateContextWithTestCertificate(TLS_method()));
  ASSERT_TRUE(server_ctx);
  EXPECT_TRUE(SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_3_VERSION));
  EXPECT_TRUE(SSL_CTX_set_min_proto_version(server_ctx.get(), TLS1_3_VERSION));

  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(client_ctx);
  EXPECT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION));
  EXPECT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));

  BIO *client_wbio = SSL_get_wbio(client.get());
  EXPECT_EQ(0u, BIO_wpending(client_wbio));
  EXPECT_TRUE(SSL_key_update(client.get(), SSL_KEY_UPDATE_NOT_REQUESTED));
  EXPECT_EQ(0u, BIO_wpending(client_wbio));
  EXPECT_EQ(0, SSL_write(client.get(), nullptr, 0));
  EXPECT_NE(0u, BIO_wpending(client_wbio));
}

TEST(SSLTest, SSLGetKeyUpdate) {
  bssl::UniquePtr<SSL_CTX> server_ctx(
      CreateContextWithTestCertificate(TLS_method()));
  ASSERT_TRUE(server_ctx);
  EXPECT_TRUE(SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_3_VERSION));
  EXPECT_TRUE(SSL_CTX_set_min_proto_version(server_ctx.get(), TLS1_3_VERSION));

  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(client_ctx);
  EXPECT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION));
  EXPECT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));

  // Initial state should be |SSL_KEY_UPDATE_NONE|.
  EXPECT_EQ(SSL_get_key_update_type(client.get()), SSL_KEY_UPDATE_NONE);

  // Test setting |SSL_key_update| with |SSL_KEY_UPDATE_REQUESTED|.
  EXPECT_TRUE(SSL_key_update(client.get(), SSL_KEY_UPDATE_REQUESTED));
  // |SSL_get_key_update_type| is used to determine whether a key update
  // operation has been scheduled but not yet performed.
  EXPECT_EQ(SSL_get_key_update_type(client.get()), SSL_KEY_UPDATE_REQUESTED);
  EXPECT_EQ(0, SSL_write(client.get(), nullptr, 0));
  // Key update operation should have been performed by now.
  EXPECT_EQ(SSL_get_key_update_type(client.get()), SSL_KEY_UPDATE_NONE);

  // Test setting |SSL_key_update| with |SSL_KEY_UPDATE_NOT_REQUESTED|.
  EXPECT_TRUE(SSL_key_update(client.get(), SSL_KEY_UPDATE_NOT_REQUESTED));
  EXPECT_EQ(SSL_get_key_update_type(client.get()),
            SSL_KEY_UPDATE_NOT_REQUESTED);
  EXPECT_EQ(0, SSL_write(client.get(), nullptr, 0));
  // Key update operation should have been performed by now.
  EXPECT_EQ(SSL_get_key_update_type(client.get()), SSL_KEY_UPDATE_NONE);
}

TEST_P(SSLVersionTest, VerifyBeforeCertRequest) {
  // Configure the server to request client certificates.
  SSL_CTX_set_custom_verify(
      server_ctx_.get(), SSL_VERIFY_PEER,
      [](SSL *ssl, uint8_t *out_alert) { return ssl_verify_ok; });

  // Configure the client to reject the server certificate.
  SSL_CTX_set_custom_verify(
      client_ctx_.get(), SSL_VERIFY_PEER,
      [](SSL *ssl, uint8_t *out_alert) { return ssl_verify_invalid; });

  // cert_cb should not be called. Verification should fail first.
  SSL_CTX_set_cert_cb(
      client_ctx_.get(),
      [](SSL *ssl, void *arg) {
        ADD_FAILURE() << "cert_cb unexpectedly called";
        return 0;
      },
      nullptr);

  bssl::UniquePtr<SSL> client, server;
  EXPECT_FALSE(ConnectClientAndServer(&client, &server, client_ctx_.get(),
                                      server_ctx_.get()));
}

// Test that ticket-based sessions on the client get fake session IDs.
TEST_P(SSLVersionTest, FakeIDsForTickets) {
  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx_.get(), SSL_SESS_CACHE_BOTH);

  bssl::UniquePtr<SSL_SESSION> session =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());
  ASSERT_TRUE(session);

  EXPECT_TRUE(SSL_SESSION_has_ticket(session.get()));
  unsigned session_id_length;
  SSL_SESSION_get_id(session.get(), &session_id_length);
  EXPECT_NE(session_id_length, 0u);
}

// These tests test multi-threaded behavior. They are intended to run with
// ThreadSanitizer.
#if defined(OPENSSL_THREADS)
TEST_P(SSLVersionTest, SessionCacheThreads) {
  SSL_CTX_set_options(server_ctx_.get(), SSL_OP_NO_TICKET);
  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx_.get(), SSL_SESS_CACHE_BOTH);

  if (version() == TLS1_3_VERSION) {
    // Our TLS 1.3 implementation does not support stateful resumption.
    ASSERT_FALSE(CreateClientSession(client_ctx_.get(), server_ctx_.get()));
    return;
  }

  // Establish two client sessions to test with.
  bssl::UniquePtr<SSL_SESSION> session1 =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());
  ASSERT_TRUE(session1);
  bssl::UniquePtr<SSL_SESSION> session2 =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());
  ASSERT_TRUE(session2);

  auto connect_with_session = [&](SSL_SESSION *session) {
    ClientConfig config;
    config.session = session;
    UniquePtr<SSL> client, server;
    ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx_.get(),
                                       server_ctx_.get(), config));
  };

  // Resume sessions in parallel with establishing new ones.
  {
    std::vector<std::thread> threads;
    threads.emplace_back([&] { connect_with_session(nullptr); });
    threads.emplace_back([&] { connect_with_session(nullptr); });
    threads.emplace_back([&] { connect_with_session(session1.get()); });
    threads.emplace_back([&] { connect_with_session(session1.get()); });
    threads.emplace_back([&] { connect_with_session(session2.get()); });
    threads.emplace_back([&] { connect_with_session(session2.get()); });
    for (auto &thread : threads) {
      thread.join();
    }
  }

  // Hit the maximum session cache size across multiple threads, to test the
  // size enforcement logic.
  size_t over_limit = 2;
  size_t limit = SSL_CTX_sess_number(server_ctx_.get()) + over_limit;
  SSL_CTX_sess_set_cache_size(server_ctx_.get(), limit);
  {
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; i++) {
      threads.emplace_back([&]() {
        connect_with_session(nullptr);
        EXPECT_LE(SSL_CTX_sess_number(server_ctx_.get()), limit);
      });
    }
    for (auto &thread : threads) {
      thread.join();
    }
    EXPECT_EQ(SSL_CTX_sess_number(server_ctx_.get()), limit);
    // We go over the cache limit by |over_limit|.
    EXPECT_EQ(SSL_CTX_sess_cache_full(server_ctx_.get()), (int)over_limit);
  }

  // Reset the session cache, this time with a mock clock.
  ASSERT_NO_FATAL_FAILURE(ResetContexts());
  SSL_CTX_set_options(server_ctx_.get(), SSL_OP_NO_TICKET);
  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_current_time_cb(server_ctx_.get(), CurrentTimeCallback);

  // Make some sessions at an arbitrary start time. Then expire them.
  g_current_time.tv_sec = 1000;
  bssl::UniquePtr<SSL_SESSION> expired_session1 =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());
  ASSERT_TRUE(expired_session1);
  bssl::UniquePtr<SSL_SESSION> expired_session2 =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());
  ASSERT_TRUE(expired_session2);
  g_current_time.tv_sec += 100 * SSL_DEFAULT_SESSION_TIMEOUT;

  session1 = CreateClientSession(client_ctx_.get(), server_ctx_.get());
  ASSERT_TRUE(session1);

  // Every 256 connections, we flush stale sessions from the session cache. Test
  // this logic is correctly synchronized with other connection attempts.
  static const int kNumConnections = 256;
  {
    std::vector<std::thread> threads;
    threads.emplace_back([&] {
      for (int i = 0; i < kNumConnections; i++) {
        connect_with_session(nullptr);
      }
    });
    threads.emplace_back([&] {
      for (int i = 0; i < kNumConnections; i++) {
        connect_with_session(nullptr);
      }
    });
    threads.emplace_back([&] {
      // Never connect with |expired_session2|. The session cache eagerly
      // removes expired sessions when it sees them. Leaving |expired_session2|
      // untouched ensures it is instead cleared by periodic flushing.
      for (int i = 0; i < kNumConnections; i++) {
        connect_with_session(expired_session1.get());
      }
    });
    threads.emplace_back([&] {
      for (int i = 0; i < kNumConnections; i++) {
        connect_with_session(session1.get());
      }
    });
    for (auto &thread : threads) {
      thread.join();
    }
  }
}

TEST_P(SSLVersionTest, SessionTicketThreads) {
  for (bool renew_ticket : {false, true}) {
    SCOPED_TRACE(renew_ticket);
    ASSERT_NO_FATAL_FAILURE(ResetContexts());
    SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
    SSL_CTX_set_session_cache_mode(server_ctx_.get(), SSL_SESS_CACHE_BOTH);
    if (renew_ticket) {
      SSL_CTX_set_tlsext_ticket_key_cb(server_ctx_.get(), RenewTicketCallback);
    }

    // Establish two client sessions to test with.
    bssl::UniquePtr<SSL_SESSION> session1 =
        CreateClientSession(client_ctx_.get(), server_ctx_.get());
    ASSERT_TRUE(session1);
    bssl::UniquePtr<SSL_SESSION> session2 =
        CreateClientSession(client_ctx_.get(), server_ctx_.get());
    ASSERT_TRUE(session2);

    auto connect_with_session = [&](SSL_SESSION *session) {
      ClientConfig config;
      config.session = session;
      UniquePtr<SSL> client, server;
      ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx_.get(),
                                         server_ctx_.get(), config));
    };

    // Resume sessions in parallel with establishing new ones.
    {
      std::vector<std::thread> threads;
      threads.emplace_back([&] { connect_with_session(nullptr); });
      threads.emplace_back([&] { connect_with_session(nullptr); });
      threads.emplace_back([&] { connect_with_session(session1.get()); });
      threads.emplace_back([&] { connect_with_session(session1.get()); });
      threads.emplace_back([&] { connect_with_session(session2.get()); });
      threads.emplace_back([&] { connect_with_session(session2.get()); });
      for (auto &thread : threads) {
        thread.join();
      }
    }
  }
}

// SSL_CTX_get0_certificate needs to lock internally. Test this works.
TEST(SSLTest, GetCertificateThreads) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  bssl::UniquePtr<X509> cert = GetTestCertificate();
  ASSERT_TRUE(cert);
  ASSERT_TRUE(SSL_CTX_use_certificate(ctx.get(), cert.get()));

  // Existing code expects |SSL_CTX_get0_certificate| to be callable from two
  // threads concurrently. It originally was an immutable operation. Now we
  // implement it with a thread-safe cache, so it is worth testing.
  X509 *cert2_thread;
  std::thread thread(
      [&] { cert2_thread = SSL_CTX_get0_certificate(ctx.get()); });
  X509 *cert2 = SSL_CTX_get0_certificate(ctx.get());
  thread.join();

  ASSERT_TRUE(cert2);
  ASSERT_TRUE(cert2_thread);
  EXPECT_EQ(cert2, cert2_thread);
  EXPECT_EQ(0, X509_cmp(cert.get(), cert2));
}

// Functions which access properties on the negotiated session are thread-safe
// where needed. Prior to TLS 1.3, clients resuming sessions and servers
// performing stateful resumption will share an underlying SSL_SESSION object,
// potentially across threads.
TEST_P(SSLVersionTest, SessionPropertiesThreads) {
  if (version() == TLS1_3_VERSION) {
    // Our TLS 1.3 implementation does not support stateful resumption.
    ASSERT_FALSE(CreateClientSession(client_ctx_.get(), server_ctx_.get()));
    return;
  }

  SSL_CTX_set_options(server_ctx_.get(), SSL_OP_NO_TICKET);
  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx_.get(), SSL_SESS_CACHE_BOTH);

  ASSERT_TRUE(UseCertAndKey(client_ctx_.get()));
  ASSERT_TRUE(UseCertAndKey(server_ctx_.get()));

  // Configure mutual authentication, so we have more session state.
  SSL_CTX_set_custom_verify(
      client_ctx_.get(), SSL_VERIFY_PEER,
      [](SSL *ssl, uint8_t *out_alert) { return ssl_verify_ok; });
  SSL_CTX_set_custom_verify(
      server_ctx_.get(), SSL_VERIFY_PEER,
      [](SSL *ssl, uint8_t *out_alert) { return ssl_verify_ok; });

  // Establish a client session to test with.
  bssl::UniquePtr<SSL_SESSION> session =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());
  ASSERT_TRUE(session);

  // Resume with it twice.
  UniquePtr<SSL> ssls[4];
  ClientConfig config;
  config.session = session.get();
  ASSERT_TRUE(ConnectClientAndServer(&ssls[0], &ssls[1], client_ctx_.get(),
                                     server_ctx_.get(), config));
  ASSERT_TRUE(ConnectClientAndServer(&ssls[2], &ssls[3], client_ctx_.get(),
                                     server_ctx_.get(), config));

  // Read properties in parallel.
  auto read_properties = [](const SSL *ssl) {
    EXPECT_TRUE(SSL_get_peer_cert_chain(ssl));
    bssl::UniquePtr<X509> peer(SSL_get_peer_certificate(ssl));
    EXPECT_TRUE(peer);
    STACK_OF(X509) *verified_chain= SSL_get0_verified_chain(ssl);
    // This test sets a custom verifier callback which doesn't actually do any verification
    EXPECT_FALSE(verified_chain);
    EXPECT_TRUE(SSL_get_current_cipher(ssl));
    EXPECT_TRUE(SSL_get_group_id(ssl));
  };

  std::vector<std::thread> threads;
  for (const auto &ssl_ptr : ssls) {
    const SSL *ssl = ssl_ptr.get();
    threads.emplace_back([=] { read_properties(ssl); });
  }
  for (auto &thread : threads) {
    thread.join();
  }
  // Session has been resumed twice.
  EXPECT_EQ(SSL_CTX_sess_hits(server_ctx_.get()), 2);
  EXPECT_EQ(SSL_CTX_sess_hits(client_ctx_.get()), 2);
}

static void SetValueOnFree(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                          int index, long argl, void *argp) {
  if (ptr != nullptr) {
    *static_cast<long *>(ptr) = argl;
  }
}

// Test that one thread can register ex_data while another thread is destroying
// an object that uses it.
TEST(SSLTest, ExDataThreads) {
  static bool already_run = false;
  if (already_run) {
    GTEST_SKIP() << "This test consumes process-global resources and can only "
                    "be run once in a process. It is not compatible with "
                    "--gtest_repeat.";
  }
  already_run = true;

  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);

  // Register an initial index, so the threads can exercise having any ex_data.
  int first_index =
      SSL_get_ex_new_index(-1, nullptr, nullptr, nullptr, SetValueOnFree);
  ASSERT_GE(first_index, 0);

  // Callers may register indices concurrently with using other indices. This
  // may happen if one part of an application is initializing while another part
  // is already running.
  static constexpr int kNumIndices = 3;
  static constexpr int kNumSSLs = 10;
  int index[kNumIndices];
  long values[kNumSSLs];
  std::fill(std::begin(values), std::end(values), -2);
  std::vector<std::thread> threads;
  for (size_t i = 0; i < kNumIndices; i++) {
    threads.emplace_back([&, i] {
      index[i] = SSL_get_ex_new_index(static_cast<long>(i), nullptr, nullptr,
                                      nullptr, SetValueOnFree);
      ASSERT_GE(index[i], 0);
    });
  }
  for (size_t i = 0; i < kNumSSLs; i++) {
    threads.emplace_back([&, i] {
      bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
      ASSERT_TRUE(ssl);
      ASSERT_TRUE(SSL_set_ex_data(ssl.get(), first_index, &values[i]));
    });
  }
  for (auto &thread : threads) {
    thread.join();
  }

  // Each of the SSL threads should have set their flag via ex_data.
  for (size_t i = 0; i < kNumSSLs; i++) {
    EXPECT_EQ(values[i], -1);
  }

  // Each of the newly-registered indices should be distinct and work correctly.
  static_assert(kNumIndices <= kNumSSLs, "values buffer too small");
  std::fill(std::begin(values), std::end(values), -2);
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);
  for (size_t i = 0; i < kNumIndices; i++) {
    for (size_t j = 0; j < i; j++) {
      EXPECT_NE(index[i], index[j]);
    }
    ASSERT_TRUE(SSL_set_ex_data(ssl.get(), index[i], &values[i]));
  }
  ssl = nullptr;
  for (size_t i = 0; i < kNumIndices; i++) {
    EXPECT_EQ(values[i], static_cast<long>(i));
  }
}
#endif  // OPENSSL_THREADS

TEST_P(SSLVersionTest, SimpleVerifiedChain) {
  ASSERT_TRUE(UseCertAndKey(server_ctx_.get()));
  ASSERT_TRUE(X509_STORE_add_cert(SSL_CTX_get_cert_store(client_ctx_.get()),
                                  cert_.get()));
  SSL_CTX_set_verify(client_ctx_.get(),
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     nullptr);
  X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(client_ctx_.get()),
                              X509_V_FLAG_NO_CHECK_TIME);


  UniquePtr<SSL> client_ssl, server_ssl;
  ClientConfig config;
  ASSERT_TRUE(ConnectClientAndServer(&client_ssl, &server_ssl, client_ctx_.get(),
                                     server_ctx_.get(), config));

  STACK_OF(X509) *client_chain = SSL_get_peer_full_cert_chain(client_ssl.get());
  STACK_OF(X509) *verified_client_chain = SSL_get0_verified_chain(client_ssl.get());
  EXPECT_TRUE(verified_client_chain);

  STACK_OF(X509) *verified_server_chain = SSL_get0_verified_chain(server_ssl.get());
  // The client didn't send a certificate so the server shouldn't have anything
  EXPECT_FALSE(verified_server_chain);

  // UseCertAndKey sets a single cert that is directly trusted, it is the only
  // one sent, and only one needed for verification
  EXPECT_EQ(sk_X509_num(client_chain), 1UL);
  EXPECT_EQ(X509_cmp(sk_X509_value(client_chain, 0), cert_.get()), 0);

  EXPECT_EQ(sk_X509_num(verified_client_chain), 1UL);
  EXPECT_EQ(X509_cmp(sk_X509_value(verified_client_chain, 0), cert_.get()), 0);
}

TEST_P(SSLVersionTest, VerifiedChain) {
  ASSERT_TRUE(X509_STORE_add_cert(SSL_CTX_get_cert_store(client_ctx_.get()),
                                  cert_.get()));
  SSL_CTX_set_verify(client_ctx_.get(),
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     nullptr);
  X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(client_ctx_.get()),
                              X509_V_FLAG_NO_CHECK_TIME);

  // UseCertAndKey sets the leaf cert the server will use and ensures the client
  // trusts the server's cert
  ASSERT_TRUE(UseCertAndKey(server_ctx_.get()));

  // Add two extra certs to the chain
  bssl::UniquePtr<STACK_OF(X509)> chain(sk_X509_new_null());
  bssl::UniquePtr<X509> cert1 = GetECDSATestCertificate();
  ASSERT_TRUE(sk_X509_push(chain.get(), cert1.get()));
  X509_up_ref(cert1.get());

  bssl::UniquePtr<X509> cert2 = GetTestCertificate();
  ASSERT_TRUE(sk_X509_push(chain.get(), cert2.get()));
  X509_up_ref(cert2.get());

  SSL_CTX_set1_chain(server_ctx_.get(), chain.get());

  UniquePtr<SSL> client_ssl, server_ssl;
  ClientConfig config;
  ASSERT_TRUE(ConnectClientAndServer(&client_ssl, &server_ssl, client_ctx_.get(),
                                     server_ctx_.get(), config));

  // The client didn't send a certificate so the server shouldn't have anything
  STACK_OF(X509) *verified_client_chain = SSL_get0_verified_chain(server_ssl.get());
  EXPECT_FALSE(verified_client_chain);
  STACK_OF(X509) *client_chain = SSL_get_peer_full_cert_chain(server_ssl.get());
  EXPECT_FALSE(client_chain);

  // The server sent a chain that the client can verify, the client directly
  // trusts the server's certificate
  STACK_OF(X509) *verified_server_chain = SSL_get0_verified_chain(client_ssl.get());
  EXPECT_EQ(sk_X509_num(verified_server_chain), 1UL);
  EXPECT_EQ(X509_cmp(sk_X509_value(verified_server_chain, 0), cert_.get()), 0);

  // The server sent two extra certs that are unneeded for verification,
  // but it is included in the unverified chain
  STACK_OF(X509) *server_chain = SSL_get_peer_full_cert_chain(client_ssl.get());
  EXPECT_EQ(sk_X509_num(server_chain), 3UL);
  EXPECT_EQ(X509_cmp(sk_X509_value(server_chain, 0), cert_.get()), 0);
  EXPECT_EQ(X509_cmp(sk_X509_value(server_chain, 1), cert1.get()), 0);
  EXPECT_EQ(X509_cmp(sk_X509_value(server_chain, 2), cert2.get()), 0);
}

TEST_P(SSLVersionTest, FailedHandshakeVerifiedChain) {
  SSL_CTX_set_verify(client_ctx_.get(),
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     nullptr);
  X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(client_ctx_.get()),
                              X509_V_FLAG_NO_CHECK_TIME);

  ASSERT_TRUE(UseCertAndKey(server_ctx_.get()));
  UniquePtr<SSL> client_ssl, server_ssl;

  ASSERT_TRUE(CreateClientAndServer(&client_ssl, &server_ssl, client_ctx_.get(), server_ctx_.get()));
  ASSERT_FALSE(CompleteHandshakes(client_ssl.get(), server_ssl.get()));
  EXPECT_NE(SSL_get_verify_result(client_ssl.get()), X509_V_OK);

  STACK_OF(X509) *client_chain = SSL_get_peer_full_cert_chain(client_ssl.get());
  ASSERT_TRUE(client_chain);
  EXPECT_EQ(sk_X509_num(client_chain), 1UL);
  EXPECT_EQ(X509_cmp(sk_X509_value(client_chain, 0), cert_.get()), 0);


  // For a failed handshake SSL_get0_verified_chain will return null
  STACK_OF(X509) *verified_client_chain = SSL_get0_verified_chain(client_ssl.get());
  EXPECT_FALSE(verified_client_chain);
}


TEST_P(SSLVersionTest, SessionMissCache) {
  if (version() == TLS1_3_VERSION) {
    // Our TLS 1.3 implementation does not support stateful resumption.
    ASSERT_FALSE(CreateClientSession(client_ctx_.get(), server_ctx_.get()));
    return;
  }

  SSL_CTX_set_options(server_ctx_.get(), SSL_OP_NO_TICKET);
  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_current_time_cb(server_ctx_.get(), CurrentTimeCallback);

  ClientConfig config;
  bssl::UniquePtr<SSL> client, server;
  // Make some sessions at an arbitrary start time. Then expire them.
  g_current_time.tv_sec = 1000;
  bssl::UniquePtr<SSL_SESSION> expired_session =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());
  ASSERT_TRUE(expired_session);
  g_current_time.tv_sec += 100 * SSL_DEFAULT_SESSION_TIMEOUT;

  static const int kNumConnections = 2;
  config.session = expired_session.get();
  EXPECT_TRUE(ConnectClientAndServer(&client, &server, client_ctx_.get(),
                                     server_ctx_.get(), config));
  EXPECT_TRUE(ConnectClientAndServer(&client, &server, client_ctx_.get(),
                                     server_ctx_.get(), config));

  // First connection is not an |sess_miss|, but failed to connect successfully.
  // Subsequent connections will all be both timeouts and misses.
  EXPECT_EQ(SSL_CTX_sess_misses(server_ctx_.get()), kNumConnections - 1);
  EXPECT_EQ(SSL_CTX_sess_timeouts(server_ctx_.get()), kNumConnections);
  // Check that |sess_hits| is not incorrectly incremented on either end.
  EXPECT_EQ(SSL_CTX_sess_hits(client_ctx_.get()), 0);
  EXPECT_EQ(SSL_CTX_sess_hits(server_ctx_.get()), 0);
}

// Callback function to force an external session cache counter update.
// This intentionally always returns a value, to verify that the counter is
// updated as intended.
// Allocating any memory within the callback function will cause the address
// sanitizers to fail, so we manage the memory externally.
static bssl::UniquePtr<SSL_SESSION> ssl_session;
static SSL_SESSION *get_session(SSL *ssl, const unsigned char *id, int idlen,
                                int *do_copy) {
  return ssl_session.release();
}

TEST_P(SSLVersionTest, SessionExternalCacheHit) {
  if (version() == TLS1_3_VERSION) {
    // Our TLS 1.3 implementation does not support stateful resumption.
    ASSERT_FALSE(CreateClientSession(client_ctx_.get(), server_ctx_.get()));
    return;
  }

  SSL_CTX_set_options(server_ctx_.get(), SSL_OP_NO_TICKET);
  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(
      server_ctx_.get(), SSL_SESS_CACHE_BOTH | SSL_SESS_CACHE_NO_INTERNAL);
  SSL_CTX_sess_set_get_cb(server_ctx_.get(), get_session);

  ClientConfig config;
  bssl::UniquePtr<SSL> client, server;
  bssl::UniquePtr<SSL_SESSION> session =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());

  static const int kNumConnections = 2;
  config.session = session.get();
  for (int i = 0; i < kNumConnections; i++) {
    ssl_session.reset(session.get());
    EXPECT_TRUE(ConnectClientAndServer(&client, &server, client_ctx_.get(),
                                       server_ctx_.get(), config));
  }
  EXPECT_EQ(SSL_CTX_sess_cb_hits(server_ctx_.get()), kNumConnections);
}

constexpr size_t kNumQUICLevels = 4;
static_assert(ssl_encryption_initial < kNumQUICLevels,
              "kNumQUICLevels is wrong");
static_assert(ssl_encryption_early_data < kNumQUICLevels,
              "kNumQUICLevels is wrong");
static_assert(ssl_encryption_handshake < kNumQUICLevels,
              "kNumQUICLevels is wrong");
static_assert(ssl_encryption_application < kNumQUICLevels,
              "kNumQUICLevels is wrong");

const char *LevelToString(ssl_encryption_level_t level) {
  switch (level) {
    case ssl_encryption_initial:
      return "initial";
    case ssl_encryption_early_data:
      return "early data";
    case ssl_encryption_handshake:
      return "handshake";
    case ssl_encryption_application:
      return "application";
  }
  return "<unknown>";
}

class MockQUICTransport {
 public:
  enum class Role { kClient, kServer };

  explicit MockQUICTransport(Role role) : role_(role) {
    // The caller is expected to configure initial secrets.
    levels_[ssl_encryption_initial].write_secret = {1};
    levels_[ssl_encryption_initial].read_secret = {1};
  }

  void set_peer(MockQUICTransport *peer) { peer_ = peer; }

  bool has_alert() const { return has_alert_; }
  ssl_encryption_level_t alert_level() const { return alert_level_; }
  uint8_t alert() const { return alert_; }

  bool PeerSecretsMatch(ssl_encryption_level_t level) const {
    return levels_[level].write_secret == peer_->levels_[level].read_secret &&
           levels_[level].read_secret == peer_->levels_[level].write_secret &&
           levels_[level].cipher == peer_->levels_[level].cipher;
  }

  bool HasReadSecret(ssl_encryption_level_t level) const {
    return !levels_[level].read_secret.empty();
  }

  bool HasWriteSecret(ssl_encryption_level_t level) const {
    return !levels_[level].write_secret.empty();
  }

  void AllowOutOfOrderWrites() { allow_out_of_order_writes_ = true; }

  bool SetReadSecret(ssl_encryption_level_t level, const SSL_CIPHER *cipher,
                     Span<const uint8_t> secret) {
    if (HasReadSecret(level)) {
      ADD_FAILURE() << LevelToString(level) << " read secret configured twice";
      return false;
    }

    if (role_ == Role::kClient && level == ssl_encryption_early_data) {
      ADD_FAILURE() << "Unexpected early data read secret";
      return false;
    }

    ssl_encryption_level_t ack_level =
        level == ssl_encryption_early_data ? ssl_encryption_application : level;
    if (!HasWriteSecret(ack_level)) {
      ADD_FAILURE() << LevelToString(level)
                    << " read secret configured before ACK write secret";
      return false;
    }

    if (cipher == nullptr) {
      ADD_FAILURE() << "Unexpected null cipher";
      return false;
    }

    if (level != ssl_encryption_early_data &&
        SSL_CIPHER_get_id(cipher) != levels_[level].cipher) {
      ADD_FAILURE() << "Cipher suite inconsistent";
      return false;
    }

    levels_[level].read_secret.assign(secret.begin(), secret.end());
    levels_[level].cipher = SSL_CIPHER_get_id(cipher);
    return true;
  }

  bool SetWriteSecret(ssl_encryption_level_t level, const SSL_CIPHER *cipher,
                      Span<const uint8_t> secret) {
    if (HasWriteSecret(level)) {
      ADD_FAILURE() << LevelToString(level) << " write secret configured twice";
      return false;
    }

    if (role_ == Role::kServer && level == ssl_encryption_early_data) {
      ADD_FAILURE() << "Unexpected early data write secret";
      return false;
    }

    if (cipher == nullptr) {
      ADD_FAILURE() << "Unexpected null cipher";
      return false;
    }

    levels_[level].write_secret.assign(secret.begin(), secret.end());
    levels_[level].cipher = SSL_CIPHER_get_id(cipher);
    return true;
  }

  bool WriteHandshakeData(ssl_encryption_level_t level,
                          Span<const uint8_t> data) {
    if (levels_[level].write_secret.empty()) {
      ADD_FAILURE() << LevelToString(level)
                    << " write secret not yet configured";
      return false;
    }

    // Although the levels are conceptually separate, BoringSSL finishes writing
    // data from a previous level before installing keys for the next level.
    if (!allow_out_of_order_writes_) {
      switch (level) {
        case ssl_encryption_early_data:
          ADD_FAILURE() << "unexpected handshake data at early data level";
          return false;
        case ssl_encryption_initial:
          if (!levels_[ssl_encryption_handshake].write_secret.empty()) {
            ADD_FAILURE()
                << LevelToString(level)
                << " handshake data written after handshake keys installed";
            return false;
          }
          OPENSSL_FALLTHROUGH;
        case ssl_encryption_handshake:
          if (!levels_[ssl_encryption_application].write_secret.empty()) {
            ADD_FAILURE()
                << LevelToString(level)
                << " handshake data written after application keys installed";
            return false;
          }
          OPENSSL_FALLTHROUGH;
        case ssl_encryption_application:
          break;
      }
    }

    levels_[level].write_data.insert(levels_[level].write_data.end(),
                                     data.begin(), data.end());
    return true;
  }

  bool SendAlert(ssl_encryption_level_t level, uint8_t alert_value) {
    if (has_alert_) {
      ADD_FAILURE() << "duplicate alert sent";
      return false;
    }

    if (levels_[level].write_secret.empty()) {
      ADD_FAILURE() << LevelToString(level)
                    << " write secret not yet configured";
      return false;
    }

    has_alert_ = true;
    alert_level_ = level;
    alert_ = alert_value;
    return true;
  }

  bool ReadHandshakeData(std::vector<uint8_t> *out,
                         ssl_encryption_level_t level,
                         size_t num = std::numeric_limits<size_t>::max()) {
    if (levels_[level].read_secret.empty()) {
      ADD_FAILURE() << "data read before keys configured in level " << level;
      return false;
    }
    // The peer may not have configured any keys yet.
    if (peer_->levels_[level].write_secret.empty()) {
      out->clear();
      return true;
    }
    // Check the peer computed the same key.
    if (peer_->levels_[level].write_secret != levels_[level].read_secret) {
      ADD_FAILURE() << "peer write key does not match read key in level "
                    << level;
      return false;
    }
    if (peer_->levels_[level].cipher != levels_[level].cipher) {
      ADD_FAILURE() << "peer cipher does not match in level " << level;
      return false;
    }
    std::vector<uint8_t> *peer_data = &peer_->levels_[level].write_data;
    num = std::min(num, peer_data->size());
    out->assign(peer_data->begin(), peer_data->begin() + num);
    peer_data->erase(peer_data->begin(), peer_data->begin() + num);
    return true;
  }

 private:
  Role role_;
  MockQUICTransport *peer_ = nullptr;

  bool allow_out_of_order_writes_ = false;
  bool has_alert_ = false;
  ssl_encryption_level_t alert_level_ = ssl_encryption_initial;
  uint8_t alert_ = 0;

  struct Level {
    std::vector<uint8_t> write_data;
    std::vector<uint8_t> write_secret;
    std::vector<uint8_t> read_secret;
    uint32_t cipher = 0;
  };
  Level levels_[kNumQUICLevels];
};

class MockQUICTransportPair {
 public:
  MockQUICTransportPair()
      : client_(MockQUICTransport::Role::kClient),
        server_(MockQUICTransport::Role::kServer) {
    client_.set_peer(&server_);
    server_.set_peer(&client_);
  }

  ~MockQUICTransportPair() {
    client_.set_peer(nullptr);
    server_.set_peer(nullptr);
  }

  MockQUICTransport *client() { return &client_; }
  MockQUICTransport *server() { return &server_; }

  bool SecretsMatch(ssl_encryption_level_t level) const {
    // We only need to check |HasReadSecret| and |HasWriteSecret| on |client_|.
    // |PeerSecretsMatch| checks that |server_| is analogously configured.
    return client_.PeerSecretsMatch(level) && client_.HasWriteSecret(level) &&
           (level == ssl_encryption_early_data || client_.HasReadSecret(level));
  }

 private:
  MockQUICTransport client_;
  MockQUICTransport server_;
};

class QUICMethodTest : public testing::Test {
 protected:
  void SetUp() override {
    client_ctx_.reset(SSL_CTX_new(TLS_method()));
    server_ctx_ = CreateContextWithTestCertificate(TLS_method());
    ASSERT_TRUE(client_ctx_);
    ASSERT_TRUE(server_ctx_);

    SSL_CTX_set_min_proto_version(server_ctx_.get(), TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(server_ctx_.get(), TLS1_3_VERSION);
    SSL_CTX_set_min_proto_version(client_ctx_.get(), TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(client_ctx_.get(), TLS1_3_VERSION);

    static const uint8_t kALPNProtos[] = {0x03, 'f', 'o', 'o'};
    ASSERT_EQ(SSL_CTX_set_alpn_protos(client_ctx_.get(), kALPNProtos,
                                      sizeof(kALPNProtos)),
              0);
    SSL_CTX_set_alpn_select_cb(
        server_ctx_.get(),
        [](SSL *ssl, const uint8_t **out, uint8_t *out_len, const uint8_t *in,
           unsigned in_len, void *arg) -> int {
          return SSL_select_next_proto(
                     const_cast<uint8_t **>(out), out_len, in, in_len,
                     kALPNProtos, sizeof(kALPNProtos)) == OPENSSL_NPN_NEGOTIATED
                     ? SSL_TLSEXT_ERR_OK
                     : SSL_TLSEXT_ERR_NOACK;
        },
        nullptr);
  }

  static MockQUICTransport *TransportFromSSL(const SSL *ssl) {
    return ex_data_.Get(ssl);
  }

  static bool ProvideHandshakeData(
      SSL *ssl, size_t num = std::numeric_limits<size_t>::max()) {
    MockQUICTransport *transport = TransportFromSSL(ssl);
    ssl_encryption_level_t level = SSL_quic_read_level(ssl);
    std::vector<uint8_t> data;
    return transport->ReadHandshakeData(&data, level, num) &&
           SSL_provide_quic_data(ssl, level, data.data(), data.size());
  }

  void AllowOutOfOrderWrites() { allow_out_of_order_writes_ = true; }

  bool CreateClientAndServer() {
    client_.reset(SSL_new(client_ctx_.get()));
    server_.reset(SSL_new(server_ctx_.get()));
    if (!client_ || !server_) {
      return false;
    }

    SSL_set_connect_state(client_.get());
    SSL_set_accept_state(server_.get());

    transport_.reset(new MockQUICTransportPair);
    if (!ex_data_.Set(client_.get(), transport_->client()) ||
        !ex_data_.Set(server_.get(), transport_->server())) {
      return false;
    }
    if (allow_out_of_order_writes_) {
      transport_->client()->AllowOutOfOrderWrites();
      transport_->server()->AllowOutOfOrderWrites();
    }
    static const uint8_t client_transport_params[] = {0};
    if (!SSL_set_quic_transport_params(client_.get(), client_transport_params,
                                       sizeof(client_transport_params)) ||
        !SSL_set_quic_transport_params(server_.get(),
                                       server_transport_params_.data(),
                                       server_transport_params_.size()) ||
        !SSL_set_quic_early_data_context(
            server_.get(), server_quic_early_data_context_.data(),
            server_quic_early_data_context_.size())) {
      return false;
    }
    return true;
  }

  enum class ExpectedError {
    kNoError,
    kClientError,
    kServerError,
  };

  // CompleteHandshakesForQUIC runs |SSL_do_handshake| on |client_| and
  // |server_| until each completes once. It returns true on success and false
  // on failure.
  bool CompleteHandshakesForQUIC() {
    return RunQUICHandshakesAndExpectError(ExpectedError::kNoError);
  }

  // Runs |SSL_do_handshake| on |client_| and |server_| until each completes
  // once. If |expect_client_error| is true, it will return true only if the
  // client handshake failed. Otherwise, it returns true if both handshakes
  // succeed and false otherwise.
  bool RunQUICHandshakesAndExpectError(ExpectedError expected_error) {
    bool client_done = false, server_done = false;
    while (!client_done || !server_done) {
      if (!client_done) {
        if (!ProvideHandshakeData(client_.get())) {
          ADD_FAILURE() << "ProvideHandshakeData(client_) failed";
          return false;
        }
        int client_ret = SSL_do_handshake(client_.get());
        int client_err = SSL_get_error(client_.get(), client_ret);
        if (client_ret == 1) {
          client_done = true;
        } else if (client_ret != -1 || client_err != SSL_ERROR_WANT_READ) {
          if (expected_error == ExpectedError::kClientError) {
            return true;
          }
          ADD_FAILURE() << "Unexpected client output: " << client_ret << " "
                        << client_err;
          return false;
        }
      }

      if (!server_done) {
        if (!ProvideHandshakeData(server_.get())) {
          ADD_FAILURE() << "ProvideHandshakeData(server_) failed";
          return false;
        }
        int server_ret = SSL_do_handshake(server_.get());
        int server_err = SSL_get_error(server_.get(), server_ret);
        if (server_ret == 1) {
          server_done = true;
        } else if (server_ret != -1 || server_err != SSL_ERROR_WANT_READ) {
          if (expected_error == ExpectedError::kServerError) {
            return true;
          }
          ADD_FAILURE() << "Unexpected server output: " << server_ret << " "
                        << server_err;
          return false;
        }
      }
    }
    return expected_error == ExpectedError::kNoError;
  }

  bssl::UniquePtr<SSL_SESSION> CreateClientSessionForQUIC() {
    g_last_session = nullptr;
    SSL_CTX_sess_set_new_cb(client_ctx_.get(), SaveLastSession);
    if (!CreateClientAndServer() || !CompleteHandshakesForQUIC()) {
      return nullptr;
    }

    // The server sent NewSessionTicket messages in the handshake.
    if (!ProvideHandshakeData(client_.get()) ||
        !SSL_process_quic_post_handshake(client_.get())) {
      return nullptr;
    }

    return std::move(g_last_session);
  }

  void ExpectHandshakeSuccess() {
    EXPECT_TRUE(transport_->SecretsMatch(ssl_encryption_application));
    EXPECT_EQ(ssl_encryption_application, SSL_quic_read_level(client_.get()));
    EXPECT_EQ(ssl_encryption_application, SSL_quic_write_level(client_.get()));
    EXPECT_EQ(ssl_encryption_application, SSL_quic_read_level(server_.get()));
    EXPECT_EQ(ssl_encryption_application, SSL_quic_write_level(server_.get()));
    EXPECT_FALSE(transport_->client()->has_alert());
    EXPECT_FALSE(transport_->server()->has_alert());

    // SSL_do_handshake is now idempotent.
    EXPECT_EQ(SSL_do_handshake(client_.get()), 1);
    EXPECT_EQ(SSL_do_handshake(server_.get()), 1);
  }

  // Returns a default SSL_QUIC_METHOD. Individual methods may be overwritten by
  // the test.
  SSL_QUIC_METHOD DefaultQUICMethod() {
    return SSL_QUIC_METHOD{
        SetReadSecretCallback, SetWriteSecretCallback, AddHandshakeDataCallback,
        FlushFlightCallback,   SendAlertCallback,
    };
  }

  static int SetReadSecretCallback(SSL *ssl, ssl_encryption_level_t level,
                                   const SSL_CIPHER *cipher,
                                   const uint8_t *secret, size_t secret_len) {
    return TransportFromSSL(ssl)->SetReadSecret(
        level, cipher, MakeConstSpan(secret, secret_len));
  }

  static int SetWriteSecretCallback(SSL *ssl, ssl_encryption_level_t level,
                                    const SSL_CIPHER *cipher,
                                    const uint8_t *secret, size_t secret_len) {
    return TransportFromSSL(ssl)->SetWriteSecret(
        level, cipher, MakeConstSpan(secret, secret_len));
  }

  static int AddHandshakeDataCallback(SSL *ssl,
                                      enum ssl_encryption_level_t level,
                                      const uint8_t *data, size_t len) {
    EXPECT_EQ(level, SSL_quic_write_level(ssl));
    return TransportFromSSL(ssl)->WriteHandshakeData(level,
                                                     MakeConstSpan(data, len));
  }

  static int FlushFlightCallback(SSL *ssl) { return 1; }

  static int SendAlertCallback(SSL *ssl, ssl_encryption_level_t level,
                               uint8_t alert) {
    EXPECT_EQ(level, SSL_quic_write_level(ssl));
    return TransportFromSSL(ssl)->SendAlert(level, alert);
  }

  bssl::UniquePtr<SSL_CTX> client_ctx_;
  bssl::UniquePtr<SSL_CTX> server_ctx_;

  static UnownedSSLExData<MockQUICTransport> ex_data_;
  std::unique_ptr<MockQUICTransportPair> transport_;

  bssl::UniquePtr<SSL> client_;
  bssl::UniquePtr<SSL> server_;

  std::vector<uint8_t> server_transport_params_ = {1};
  std::vector<uint8_t> server_quic_early_data_context_ = {2};

  bool allow_out_of_order_writes_ = false;
};

UnownedSSLExData<MockQUICTransport> QUICMethodTest::ex_data_;

// Test a full handshake and resumption work.
TEST_F(QUICMethodTest, Basic) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();

  g_last_session = nullptr;

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_sess_set_new_cb(client_ctx_.get(), SaveLastSession);
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  ASSERT_TRUE(CreateClientAndServer());
  ASSERT_TRUE(CompleteHandshakesForQUIC());

  ExpectHandshakeSuccess();
  EXPECT_FALSE(SSL_session_reused(client_.get()));
  EXPECT_FALSE(SSL_session_reused(server_.get()));

  // The server sent NewSessionTicket messages in the handshake.
  EXPECT_FALSE(g_last_session);
  ASSERT_TRUE(ProvideHandshakeData(client_.get()));
  EXPECT_EQ(SSL_process_quic_post_handshake(client_.get()), 1);
  EXPECT_TRUE(g_last_session);

  // Create a second connection to verify resumption works.
  ASSERT_TRUE(CreateClientAndServer());
  bssl::UniquePtr<SSL_SESSION> session = std::move(g_last_session);
  SSL_set_session(client_.get(), session.get());

  ASSERT_TRUE(CompleteHandshakesForQUIC());

  ExpectHandshakeSuccess();
  EXPECT_TRUE(SSL_session_reused(client_.get()));
  EXPECT_TRUE(SSL_session_reused(server_.get()));
}

// Test that HelloRetryRequest in QUIC works.
TEST_F(QUICMethodTest, HelloRetryRequest) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();

  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  // BoringSSL predicts the most preferred ECDH group, so using different
  // preferences will trigger HelloRetryRequest.
  static const int kClientPrefs[] = {NID_X25519, NID_X9_62_prime256v1};
  ASSERT_TRUE(SSL_CTX_set1_groups(client_ctx_.get(), kClientPrefs,
                                  OPENSSL_ARRAY_SIZE(kClientPrefs)));
  static const int kServerPrefs[] = {NID_X9_62_prime256v1, NID_X25519};
  ASSERT_TRUE(SSL_CTX_set1_groups(server_ctx_.get(), kServerPrefs,
                                  OPENSSL_ARRAY_SIZE(kServerPrefs)));

  ASSERT_TRUE(CreateClientAndServer());
  ASSERT_TRUE(CompleteHandshakesForQUIC());
  ExpectHandshakeSuccess();
}

// Test that the client does not send a legacy_session_id in the ClientHello.
TEST_F(QUICMethodTest, NoLegacySessionId) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();

  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));
  // Check that the session ID length is 0 in an early callback.
  SSL_CTX_set_select_certificate_cb(
      server_ctx_.get(),
      [](const SSL_CLIENT_HELLO *client_hello) -> ssl_select_cert_result_t {
        EXPECT_EQ(client_hello->session_id_len, 0u);
        return ssl_select_cert_success;
      });

  ASSERT_TRUE(CreateClientAndServer());
  ASSERT_TRUE(CompleteHandshakesForQUIC());

  ExpectHandshakeSuccess();
}

// Test that, even in a 1-RTT handshake, the server installs keys at the right
// time. Half-RTT keys are available early, but 1-RTT read keys are deferred.
TEST_F(QUICMethodTest, HalfRTTKeys) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();

  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));
  ASSERT_TRUE(CreateClientAndServer());

  // The client sends ClientHello.
  ASSERT_EQ(SSL_do_handshake(client_.get()), -1);
  ASSERT_EQ(SSL_ERROR_WANT_READ, SSL_get_error(client_.get(), -1));

  // The server reads ClientHello and sends ServerHello..Finished.
  ASSERT_TRUE(ProvideHandshakeData(server_.get()));
  ASSERT_EQ(SSL_do_handshake(server_.get()), -1);
  ASSERT_EQ(SSL_ERROR_WANT_READ, SSL_get_error(server_.get(), -1));

  // At this point, the server has half-RTT write keys, but it cannot access
  // 1-RTT read keys until client Finished.
  EXPECT_TRUE(transport_->server()->HasWriteSecret(ssl_encryption_application));
  EXPECT_FALSE(transport_->server()->HasReadSecret(ssl_encryption_application));

  // Finish up the client and server handshakes.
  ASSERT_TRUE(CompleteHandshakesForQUIC());

  // Both sides can now exchange 1-RTT data.
  ExpectHandshakeSuccess();
}

TEST_F(QUICMethodTest, ZeroRTTAccept) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_early_data_enabled(client_ctx_.get(), 1);
  SSL_CTX_set_early_data_enabled(server_ctx_.get(), 1);
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  bssl::UniquePtr<SSL_SESSION> session = CreateClientSessionForQUIC();
  ASSERT_TRUE(session);

  ASSERT_TRUE(CreateClientAndServer());
  SSL_set_session(client_.get(), session.get());

  EXPECT_FALSE(SSL_get_client_ciphers(client_.get()));
  EXPECT_FALSE(SSL_get_client_ciphers(server_.get()));

  // The client handshake should return immediately into the early data state.
  ASSERT_EQ(SSL_do_handshake(client_.get()), 1);
  EXPECT_TRUE(SSL_in_early_data(client_.get()));
  // The transport should have keys for sending 0-RTT data.
  EXPECT_TRUE(transport_->client()->HasWriteSecret(ssl_encryption_early_data));

  // The server will consume the ClientHello and also enter the early data
  // state.
  ASSERT_TRUE(ProvideHandshakeData(server_.get()));
  ASSERT_EQ(SSL_do_handshake(server_.get()), 1);
  EXPECT_TRUE(SSL_in_early_data(server_.get()));
  EXPECT_TRUE(transport_->SecretsMatch(ssl_encryption_early_data));
  // At this point, the server has half-RTT write keys, but it cannot access
  // 1-RTT read keys until client Finished.
  EXPECT_TRUE(transport_->server()->HasWriteSecret(ssl_encryption_application));
  EXPECT_FALSE(transport_->server()->HasReadSecret(ssl_encryption_application));
  // The client should still have no view of the server's preferences, but the
  // server should have seen at least one cipher from the client.
  EXPECT_FALSE(SSL_get_client_ciphers(client_.get()));
  EXPECT_GT(sk_SSL_CIPHER_num(SSL_get_client_ciphers(server_.get())), (size_t) 0);

  // Finish up the client and server handshakes.
  ASSERT_TRUE(CompleteHandshakesForQUIC());

  // Both sides can now exchange 1-RTT data.
  ExpectHandshakeSuccess();
  EXPECT_TRUE(SSL_session_reused(client_.get()));
  EXPECT_TRUE(SSL_session_reused(server_.get()));
  EXPECT_FALSE(SSL_in_early_data(client_.get()));
  EXPECT_FALSE(SSL_in_early_data(server_.get()));
  EXPECT_TRUE(SSL_early_data_accepted(client_.get()));
  EXPECT_TRUE(SSL_early_data_accepted(server_.get()));

  // Finish handling post-handshake messages after the first 0-RTT resumption.
  EXPECT_TRUE(ProvideHandshakeData(client_.get()));
  EXPECT_TRUE(SSL_process_quic_post_handshake(client_.get()));

  // Perform a second 0-RTT resumption attempt, and confirm that 0-RTT is
  // accepted again.
  ASSERT_TRUE(CreateClientAndServer());
  SSL_set_session(client_.get(), g_last_session.get());

  // The client handshake should return immediately into the early data state.
  ASSERT_EQ(SSL_do_handshake(client_.get()), 1);
  EXPECT_TRUE(SSL_in_early_data(client_.get()));
  // The transport should have keys for sending 0-RTT data.
  EXPECT_TRUE(transport_->client()->HasWriteSecret(ssl_encryption_early_data));

  // The server will consume the ClientHello and also enter the early data
  // state.
  ASSERT_TRUE(ProvideHandshakeData(server_.get()));
  ASSERT_EQ(SSL_do_handshake(server_.get()), 1);
  EXPECT_TRUE(SSL_in_early_data(server_.get()));
  EXPECT_TRUE(transport_->SecretsMatch(ssl_encryption_early_data));
  // At this point, the server has half-RTT write keys, but it cannot access
  // 1-RTT read keys until client Finished.
  EXPECT_TRUE(transport_->server()->HasWriteSecret(ssl_encryption_application));
  EXPECT_FALSE(transport_->server()->HasReadSecret(ssl_encryption_application));

  // Finish up the client and server handshakes.
  ASSERT_TRUE(CompleteHandshakesForQUIC());

  // Both sides can now exchange 1-RTT data.
  ExpectHandshakeSuccess();
  EXPECT_TRUE(SSL_session_reused(client_.get()));
  EXPECT_TRUE(SSL_session_reused(server_.get()));
  EXPECT_FALSE(SSL_in_early_data(client_.get()));
  EXPECT_FALSE(SSL_in_early_data(server_.get()));
  EXPECT_TRUE(SSL_early_data_accepted(client_.get()));
  EXPECT_TRUE(SSL_early_data_accepted(server_.get()));
  EXPECT_EQ(SSL_get_early_data_reason(client_.get()), ssl_early_data_accepted);
  EXPECT_EQ(SSL_get_early_data_reason(server_.get()), ssl_early_data_accepted);
}

TEST_F(QUICMethodTest, ZeroRTTRejectMismatchedParameters) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_early_data_enabled(client_ctx_.get(), 1);
  SSL_CTX_set_early_data_enabled(server_ctx_.get(), 1);
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));


  bssl::UniquePtr<SSL_SESSION> session = CreateClientSessionForQUIC();
  ASSERT_TRUE(session);

  ASSERT_TRUE(CreateClientAndServer());
  static const uint8_t new_context[] = {4};
  ASSERT_TRUE(SSL_set_quic_early_data_context(server_.get(), new_context,
                                              sizeof(new_context)));
  SSL_set_session(client_.get(), session.get());

  // The client handshake should return immediately into the early data
  // state.
  ASSERT_EQ(SSL_do_handshake(client_.get()), 1);
  EXPECT_TRUE(SSL_in_early_data(client_.get()));
  // The transport should have keys for sending 0-RTT data.
  EXPECT_TRUE(transport_->client()->HasWriteSecret(ssl_encryption_early_data));

  // The server will consume the ClientHello, but it will not accept 0-RTT.
  ASSERT_TRUE(ProvideHandshakeData(server_.get()));
  ASSERT_EQ(SSL_do_handshake(server_.get()), -1);
  ASSERT_EQ(SSL_ERROR_WANT_READ, SSL_get_error(server_.get(), -1));
  EXPECT_FALSE(SSL_in_early_data(server_.get()));
  EXPECT_FALSE(transport_->server()->HasReadSecret(ssl_encryption_early_data));

  // The client consumes the server response and signals 0-RTT rejection.
  for (;;) {
    ASSERT_TRUE(ProvideHandshakeData(client_.get()));
    ASSERT_EQ(-1, SSL_do_handshake(client_.get()));
    int err = SSL_get_error(client_.get(), -1);
    if (err == SSL_ERROR_EARLY_DATA_REJECTED) {
      break;
    }
    ASSERT_EQ(SSL_ERROR_WANT_READ, err);
  }

  // As in TLS over TCP, 0-RTT rejection is sticky.
  ASSERT_EQ(-1, SSL_do_handshake(client_.get()));
  ASSERT_EQ(SSL_ERROR_EARLY_DATA_REJECTED, SSL_get_error(client_.get(), -1));

  // Finish up the client and server handshakes.
  SSL_reset_early_data_reject(client_.get());
  ASSERT_TRUE(CompleteHandshakesForQUIC());

  // Both sides can now exchange 1-RTT data.
  ExpectHandshakeSuccess();
  EXPECT_TRUE(SSL_session_reused(client_.get()));
  EXPECT_TRUE(SSL_session_reused(server_.get()));
  EXPECT_FALSE(SSL_in_early_data(client_.get()));
  EXPECT_FALSE(SSL_in_early_data(server_.get()));
  EXPECT_FALSE(SSL_early_data_accepted(client_.get()));
  EXPECT_FALSE(SSL_early_data_accepted(server_.get()));
}

TEST_F(QUICMethodTest, NoZeroRTTTicketWithoutEarlyDataContext) {
  server_quic_early_data_context_ = {};
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_early_data_enabled(client_ctx_.get(), 1);
  SSL_CTX_set_early_data_enabled(server_ctx_.get(), 1);
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  bssl::UniquePtr<SSL_SESSION> session = CreateClientSessionForQUIC();
  ASSERT_TRUE(session);
  EXPECT_FALSE(SSL_SESSION_early_data_capable(session.get()));
}

TEST_F(QUICMethodTest, ZeroRTTReject) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_early_data_enabled(client_ctx_.get(), 1);
  SSL_CTX_set_early_data_enabled(server_ctx_.get(), 1);
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  bssl::UniquePtr<SSL_SESSION> session = CreateClientSessionForQUIC();
  ASSERT_TRUE(session);

  for (bool reject_hrr : {false, true}) {
    SCOPED_TRACE(reject_hrr);

    ASSERT_TRUE(CreateClientAndServer());
    if (reject_hrr) {
      // Configure the server to prefer P-256, which will reject 0-RTT via
      // HelloRetryRequest.
      int p256 = NID_X9_62_prime256v1;
      ASSERT_TRUE(SSL_set1_groups(server_.get(), &p256, 1));
    } else {
      // Disable 0-RTT on the server, so it will reject it.
      SSL_set_early_data_enabled(server_.get(), 0);
    }
    SSL_set_session(client_.get(), session.get());

    // The client handshake should return immediately into the early data state.
    ASSERT_EQ(SSL_do_handshake(client_.get()), 1);
    EXPECT_TRUE(SSL_in_early_data(client_.get()));
    // The transport should have keys for sending 0-RTT data.
    EXPECT_TRUE(
        transport_->client()->HasWriteSecret(ssl_encryption_early_data));

    // The server will consume the ClientHello, but it will not accept 0-RTT.
    ASSERT_TRUE(ProvideHandshakeData(server_.get()));
    ASSERT_EQ(SSL_do_handshake(server_.get()), -1);
    ASSERT_EQ(SSL_ERROR_WANT_READ, SSL_get_error(server_.get(), -1));
    EXPECT_FALSE(SSL_in_early_data(server_.get()));
    EXPECT_FALSE(
        transport_->server()->HasReadSecret(ssl_encryption_early_data));

    // The client consumes the server response and signals 0-RTT rejection.
    for (;;) {
      ASSERT_TRUE(ProvideHandshakeData(client_.get()));
      ASSERT_EQ(-1, SSL_do_handshake(client_.get()));
      int err = SSL_get_error(client_.get(), -1);
      if (err == SSL_ERROR_EARLY_DATA_REJECTED) {
        break;
      }
      ASSERT_EQ(SSL_ERROR_WANT_READ, err);
    }

    // As in TLS over TCP, 0-RTT rejection is sticky.
    ASSERT_EQ(-1, SSL_do_handshake(client_.get()));
    ASSERT_EQ(SSL_ERROR_EARLY_DATA_REJECTED, SSL_get_error(client_.get(), -1));

    // Finish up the client and server handshakes.
    SSL_reset_early_data_reject(client_.get());
    ASSERT_TRUE(CompleteHandshakesForQUIC());

    // Both sides can now exchange 1-RTT data.
    ExpectHandshakeSuccess();
    EXPECT_TRUE(SSL_session_reused(client_.get()));
    EXPECT_TRUE(SSL_session_reused(server_.get()));
    EXPECT_FALSE(SSL_in_early_data(client_.get()));
    EXPECT_FALSE(SSL_in_early_data(server_.get()));
    EXPECT_FALSE(SSL_early_data_accepted(client_.get()));
    EXPECT_FALSE(SSL_early_data_accepted(server_.get()));
  }
}

TEST_F(QUICMethodTest, NoZeroRTTKeysBeforeReverify) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_early_data_enabled(client_ctx_.get(), 1);
  SSL_CTX_set_reverify_on_resume(client_ctx_.get(), 1);
  SSL_CTX_set_early_data_enabled(server_ctx_.get(), 1);
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  bssl::UniquePtr<SSL_SESSION> session = CreateClientSessionForQUIC();
  ASSERT_TRUE(session);

  ASSERT_TRUE(CreateClientAndServer());
  SSL_set_session(client_.get(), session.get());

  // Configure the certificate (re)verification to never complete. The client
  // handshake should pause.
  SSL_set_custom_verify(
      client_.get(), SSL_VERIFY_PEER,
      [](SSL *ssl, uint8_t *out_alert) -> ssl_verify_result_t {
        return ssl_verify_retry;
      });
  ASSERT_EQ(SSL_do_handshake(client_.get()), -1);
  ASSERT_EQ(SSL_get_error(client_.get(), -1),
            SSL_ERROR_WANT_CERTIFICATE_VERIFY);

  // The early data keys have not yet been released.
  EXPECT_FALSE(transport_->client()->HasWriteSecret(ssl_encryption_early_data));

  // After the verification completes, the handshake progresses to the 0-RTT
  // point and releases keys.
  SSL_set_custom_verify(
      client_.get(), SSL_VERIFY_PEER,
      [](SSL *ssl, uint8_t *out_alert) -> ssl_verify_result_t {
        return ssl_verify_ok;
      });
  ASSERT_EQ(SSL_do_handshake(client_.get()), 1);
  EXPECT_TRUE(SSL_in_early_data(client_.get()));
  EXPECT_TRUE(transport_->client()->HasWriteSecret(ssl_encryption_early_data));
}

// Test only releasing data to QUIC one byte at a time on request, to maximize
// state machine pauses. Additionally, test that existing asynchronous callbacks
// still work.
TEST_F(QUICMethodTest, Async) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();

  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));
  ASSERT_TRUE(CreateClientAndServer());

  // Install an asynchronous certificate callback.
  bool cert_cb_ok = false;
  SSL_set_cert_cb(
      server_.get(),
      [](SSL *, void *arg) -> int {
        return *static_cast<bool *>(arg) ? 1 : -1;
      },
      &cert_cb_ok);

  for (;;) {
    int client_ret = SSL_do_handshake(client_.get());
    if (client_ret != 1) {
      ASSERT_EQ(client_ret, -1);
      ASSERT_EQ(SSL_get_error(client_.get(), client_ret), SSL_ERROR_WANT_READ);
      ASSERT_TRUE(ProvideHandshakeData(client_.get(), 1));
    }

    int server_ret = SSL_do_handshake(server_.get());
    if (server_ret != 1) {
      ASSERT_EQ(server_ret, -1);
      int ssl_err = SSL_get_error(server_.get(), server_ret);
      switch (ssl_err) {
        case SSL_ERROR_WANT_READ:
          ASSERT_TRUE(ProvideHandshakeData(server_.get(), 1));
          break;
        case SSL_ERROR_WANT_X509_LOOKUP:
          ASSERT_FALSE(cert_cb_ok);
          cert_cb_ok = true;
          break;
        default:
          FAIL() << "Unexpected SSL_get_error result: " << ssl_err;
      }
    }

    if (client_ret == 1 && server_ret == 1) {
      break;
    }
  }

  ExpectHandshakeSuccess();
}

// Test buffering write data until explicit flushes.
TEST_F(QUICMethodTest, Buffered) {
  AllowOutOfOrderWrites();

  struct BufferedFlight {
    std::vector<uint8_t> data[kNumQUICLevels];
  };
  static UnownedSSLExData<BufferedFlight> buffered_flights;

  auto add_handshake_data = [](SSL *ssl, enum ssl_encryption_level_t level,
                               const uint8_t *data, size_t len) -> int {
    BufferedFlight *flight = buffered_flights.Get(ssl);
    flight->data[level].insert(flight->data[level].end(), data, data + len);
    return 1;
  };

  auto flush_flight = [](SSL *ssl) -> int {
    BufferedFlight *flight = buffered_flights.Get(ssl);
    for (size_t level = 0; level < kNumQUICLevels; level++) {
      if (!flight->data[level].empty()) {
        if (!TransportFromSSL(ssl)->WriteHandshakeData(
                static_cast<ssl_encryption_level_t>(level),
                flight->data[level])) {
          return 0;
        }
        flight->data[level].clear();
      }
    }
    return 1;
  };

  SSL_QUIC_METHOD quic_method = DefaultQUICMethod();
  quic_method.add_handshake_data = add_handshake_data;
  quic_method.flush_flight = flush_flight;

  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));
  ASSERT_TRUE(CreateClientAndServer());

  BufferedFlight client_flight, server_flight;
  ASSERT_TRUE(buffered_flights.Set(client_.get(), &client_flight));
  ASSERT_TRUE(buffered_flights.Set(server_.get(), &server_flight));

  ASSERT_TRUE(CompleteHandshakesForQUIC());

  ExpectHandshakeSuccess();
}

// Test that excess data at one level is rejected. That is, if a single
// |SSL_provide_quic_data| call included both ServerHello and
// EncryptedExtensions in a single chunk, BoringSSL notices and rejects this on
// key change.
TEST_F(QUICMethodTest, ExcessProvidedData) {
  AllowOutOfOrderWrites();

  auto add_handshake_data = [](SSL *ssl, enum ssl_encryption_level_t level,
                               const uint8_t *data, size_t len) -> int {
    // Switch everything to the initial level.
    return TransportFromSSL(ssl)->WriteHandshakeData(ssl_encryption_initial,
                                                     MakeConstSpan(data, len));
  };

  SSL_QUIC_METHOD quic_method = DefaultQUICMethod();
  quic_method.add_handshake_data = add_handshake_data;

  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));
  ASSERT_TRUE(CreateClientAndServer());

  // Send the ClientHello and ServerHello through Finished.
  ASSERT_EQ(SSL_do_handshake(client_.get()), -1);
  ASSERT_EQ(SSL_get_error(client_.get(), -1), SSL_ERROR_WANT_READ);
  ASSERT_TRUE(ProvideHandshakeData(server_.get()));
  ASSERT_EQ(SSL_do_handshake(server_.get()), -1);
  ASSERT_EQ(SSL_get_error(server_.get(), -1), SSL_ERROR_WANT_READ);

  // The client is still waiting for the ServerHello at initial
  // encryption.
  ASSERT_EQ(ssl_encryption_initial, SSL_quic_read_level(client_.get()));

  // |add_handshake_data| incorrectly wrote everything at the initial level, so
  // this queues up ServerHello through Finished in one chunk.
  ASSERT_TRUE(ProvideHandshakeData(client_.get()));

  // The client reads ServerHello successfully, but then rejects the buffered
  // EncryptedExtensions on key change.
  ASSERT_EQ(SSL_do_handshake(client_.get()), -1);
  ASSERT_EQ(SSL_get_error(client_.get(), -1), SSL_ERROR_SSL);
  EXPECT_TRUE(
      ErrorEquals(ERR_get_error(), ERR_LIB_SSL, SSL_R_EXCESS_HANDSHAKE_DATA));

  // The client sends an alert in response to this. The alert is sent at
  // handshake level because we install write secrets before read secrets and
  // the error is discovered when installing the read secret. (How to send
  // alerts on protocol syntax errors near key changes is ambiguous in general.)
  ASSERT_TRUE(transport_->client()->has_alert());
  EXPECT_EQ(transport_->client()->alert_level(), ssl_encryption_handshake);
  EXPECT_EQ(transport_->client()->alert(), SSL_AD_UNEXPECTED_MESSAGE);

  // Sanity-check handshake secrets. The error is discovered while setting the
  // read secret, so only the write secret has been installed.
  EXPECT_TRUE(transport_->client()->HasWriteSecret(ssl_encryption_handshake));
  EXPECT_FALSE(transport_->client()->HasReadSecret(ssl_encryption_handshake));
}

// Test that |SSL_provide_quic_data| will reject data at the wrong level.
TEST_F(QUICMethodTest, ProvideWrongLevel) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();

  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));
  ASSERT_TRUE(CreateClientAndServer());

  // Send the ClientHello and ServerHello through Finished.
  ASSERT_EQ(SSL_do_handshake(client_.get()), -1);
  ASSERT_EQ(SSL_get_error(client_.get(), -1), SSL_ERROR_WANT_READ);
  ASSERT_TRUE(ProvideHandshakeData(server_.get()));
  ASSERT_EQ(SSL_do_handshake(server_.get()), -1);
  ASSERT_EQ(SSL_get_error(server_.get(), -1), SSL_ERROR_WANT_READ);

  // The client is still waiting for the ServerHello at initial
  // encryption.
  ASSERT_EQ(ssl_encryption_initial, SSL_quic_read_level(client_.get()));

  // Data cannot be provided at the next level.
  std::vector<uint8_t> data;
  ASSERT_TRUE(
      transport_->client()->ReadHandshakeData(&data, ssl_encryption_initial));
  ASSERT_FALSE(SSL_provide_quic_data(client_.get(), ssl_encryption_handshake,
                                     data.data(), data.size()));
  ERR_clear_error();

  // Progress to EncryptedExtensions.
  ASSERT_TRUE(SSL_provide_quic_data(client_.get(), ssl_encryption_initial,
                                    data.data(), data.size()));
  ASSERT_EQ(SSL_do_handshake(client_.get()), -1);
  ASSERT_EQ(SSL_get_error(client_.get(), -1), SSL_ERROR_WANT_READ);
  ASSERT_EQ(ssl_encryption_handshake, SSL_quic_read_level(client_.get()));

  // Data cannot be provided at the previous level.
  ASSERT_TRUE(
      transport_->client()->ReadHandshakeData(&data, ssl_encryption_handshake));
  ASSERT_FALSE(SSL_provide_quic_data(client_.get(), ssl_encryption_initial,
                                     data.data(), data.size()));
}

TEST_F(QUICMethodTest, TooMuchData) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();

  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));
  ASSERT_TRUE(CreateClientAndServer());

  size_t limit =
      SSL_quic_max_handshake_flight_len(client_.get(), ssl_encryption_initial);
  uint8_t b = 0;
  for (size_t i = 0; i < limit; i++) {
    ASSERT_TRUE(
        SSL_provide_quic_data(client_.get(), ssl_encryption_initial, &b, 1));
  }

  EXPECT_FALSE(
      SSL_provide_quic_data(client_.get(), ssl_encryption_initial, &b, 1));
}

// Provide invalid post-handshake data.
TEST_F(QUICMethodTest, BadPostHandshake) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();

  g_last_session = nullptr;

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_sess_set_new_cb(client_ctx_.get(), SaveLastSession);
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));
  ASSERT_TRUE(CreateClientAndServer());
  ASSERT_TRUE(CompleteHandshakesForQUIC());

  EXPECT_EQ(SSL_do_handshake(client_.get()), 1);
  EXPECT_EQ(SSL_do_handshake(server_.get()), 1);
  EXPECT_TRUE(transport_->SecretsMatch(ssl_encryption_application));
  EXPECT_FALSE(transport_->client()->has_alert());
  EXPECT_FALSE(transport_->server()->has_alert());

  // Junk sent as part of post-handshake data should cause an error.
  uint8_t kJunk[] = {0x17, 0x0, 0x0, 0x4, 0xB, 0xE, 0xE, 0xF};
  ASSERT_TRUE(SSL_provide_quic_data(client_.get(), ssl_encryption_application,
                                    kJunk, sizeof(kJunk)));
  EXPECT_EQ(SSL_process_quic_post_handshake(client_.get()), 0);
}

static void ExpectReceivedTransportParamsEqual(const SSL *ssl,
                                               Span<const uint8_t> expected) {
  const uint8_t *received;
  size_t received_len;
  SSL_get_peer_quic_transport_params(ssl, &received, &received_len);
  ASSERT_EQ(received_len, expected.size());
  EXPECT_EQ(Bytes(received, received_len), Bytes(expected));
}

TEST_F(QUICMethodTest, SetTransportParameters) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  ASSERT_TRUE(CreateClientAndServer());
  uint8_t kClientParams[] = {1, 2, 3, 4};
  uint8_t kServerParams[] = {5, 6, 7};
  ASSERT_TRUE(SSL_set_quic_transport_params(client_.get(), kClientParams,
                                            sizeof(kClientParams)));
  ASSERT_TRUE(SSL_set_quic_transport_params(server_.get(), kServerParams,
                                            sizeof(kServerParams)));

  ASSERT_TRUE(CompleteHandshakesForQUIC());
  ExpectReceivedTransportParamsEqual(client_.get(), kServerParams);
  ExpectReceivedTransportParamsEqual(server_.get(), kClientParams);
}

TEST_F(QUICMethodTest, SetTransportParamsInCallback) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  ASSERT_TRUE(CreateClientAndServer());
  uint8_t kClientParams[] = {1, 2, 3, 4};
  static uint8_t kServerParams[] = {5, 6, 7};
  ASSERT_TRUE(SSL_set_quic_transport_params(client_.get(), kClientParams,
                                            sizeof(kClientParams)));
  SSL_CTX_set_tlsext_servername_callback(
      server_ctx_.get(), [](SSL *ssl, int *out_alert, void *arg) -> int {
        EXPECT_TRUE(SSL_set_quic_transport_params(ssl, kServerParams,
                                                  sizeof(kServerParams)));
        return SSL_TLSEXT_ERR_OK;
      });

  ASSERT_TRUE(CompleteHandshakesForQUIC());
  ExpectReceivedTransportParamsEqual(client_.get(), kServerParams);
  ExpectReceivedTransportParamsEqual(server_.get(), kClientParams);
}

TEST_F(QUICMethodTest, ForbidCrossProtocolResumptionClient) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();

  g_last_session = nullptr;

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_sess_set_new_cb(client_ctx_.get(), SaveLastSession);
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  ASSERT_TRUE(CreateClientAndServer());
  ASSERT_TRUE(CompleteHandshakesForQUIC());

  ExpectHandshakeSuccess();
  EXPECT_FALSE(SSL_session_reused(client_.get()));
  EXPECT_FALSE(SSL_session_reused(server_.get()));

  // The server sent NewSessionTicket messages in the handshake.
  EXPECT_FALSE(g_last_session);
  ASSERT_TRUE(ProvideHandshakeData(client_.get()));
  EXPECT_EQ(SSL_process_quic_post_handshake(client_.get()), 1);
  ASSERT_TRUE(g_last_session);

  // Pretend that g_last_session came from a TLS-over-TCP connection.
  g_last_session->is_quic = false;

  // Create a second connection and verify that resumption does not occur with
  // a session from a non-QUIC connection. This tests that the client does not
  // offer over QUIC a session believed to be received over TCP. The server
  // believes this is a QUIC session, so if the client offered the session, the
  // server would have resumed it.
  ASSERT_TRUE(CreateClientAndServer());
  bssl::UniquePtr<SSL_SESSION> session = std::move(g_last_session);
  SSL_set_session(client_.get(), session.get());

  ASSERT_TRUE(CompleteHandshakesForQUIC());
  ExpectHandshakeSuccess();
  EXPECT_FALSE(SSL_session_reused(client_.get()));
  EXPECT_FALSE(SSL_session_reused(server_.get()));
}

TEST_F(QUICMethodTest, ForbidCrossProtocolResumptionServer) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();

  g_last_session = nullptr;

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_sess_set_new_cb(client_ctx_.get(), SaveLastSession);
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  ASSERT_TRUE(CreateClientAndServer());
  ASSERT_TRUE(CompleteHandshakesForQUIC());

  ExpectHandshakeSuccess();
  EXPECT_FALSE(SSL_session_reused(client_.get()));
  EXPECT_FALSE(SSL_session_reused(server_.get()));

  // The server sent NewSessionTicket messages in the handshake.
  EXPECT_FALSE(g_last_session);
  ASSERT_TRUE(ProvideHandshakeData(client_.get()));
  EXPECT_EQ(SSL_process_quic_post_handshake(client_.get()), 1);
  ASSERT_TRUE(g_last_session);

  // Attempt a resumption with g_last_session using TLS_method.
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(client_ctx);

  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), nullptr));

  bssl::UniquePtr<SSL> client(SSL_new(client_ctx.get())),
      server(SSL_new(server_ctx_.get()));
  ASSERT_TRUE(client);
  ASSERT_TRUE(server);
  SSL_set_connect_state(client.get());
  SSL_set_accept_state(server.get());

  // The TLS-over-TCP client will refuse to resume with a quic session, so
  // mark is_quic = false to bypass the client check to test the server check.
  g_last_session->is_quic = false;
  SSL_set_session(client.get(), g_last_session.get());

  BIO *bio1, *bio2;
  ASSERT_TRUE(BIO_new_bio_pair(&bio1, 0, &bio2, 0));

  // SSL_set_bio takes ownership.
  SSL_set_bio(client.get(), bio1, bio1);
  SSL_set_bio(server.get(), bio2, bio2);
  ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));

  EXPECT_FALSE(SSL_session_reused(client.get()));
  EXPECT_FALSE(SSL_session_reused(server.get()));
}

TEST_F(QUICMethodTest, ClientRejectsMissingTransportParams) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  ASSERT_TRUE(CreateClientAndServer());
  ASSERT_TRUE(SSL_set_quic_transport_params(server_.get(), nullptr, 0));
  ASSERT_TRUE(RunQUICHandshakesAndExpectError(ExpectedError::kServerError));
}

TEST_F(QUICMethodTest, ServerRejectsMissingTransportParams) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  ASSERT_TRUE(CreateClientAndServer());
  ASSERT_TRUE(SSL_set_quic_transport_params(client_.get(), nullptr, 0));
  ASSERT_TRUE(RunQUICHandshakesAndExpectError(ExpectedError::kClientError));
}

TEST_F(QUICMethodTest, QuicLegacyCodepointEnabled) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  ASSERT_TRUE(CreateClientAndServer());
  uint8_t kClientParams[] = {1, 2, 3, 4};
  uint8_t kServerParams[] = {5, 6, 7};
  SSL_set_quic_use_legacy_codepoint(client_.get(), 1);
  SSL_set_quic_use_legacy_codepoint(server_.get(), 1);
  ASSERT_TRUE(SSL_set_quic_transport_params(client_.get(), kClientParams,
                                            sizeof(kClientParams)));
  ASSERT_TRUE(SSL_set_quic_transport_params(server_.get(), kServerParams,
                                            sizeof(kServerParams)));

  ASSERT_TRUE(CompleteHandshakesForQUIC());
  ExpectReceivedTransportParamsEqual(client_.get(), kServerParams);
  ExpectReceivedTransportParamsEqual(server_.get(), kClientParams);
}

TEST_F(QUICMethodTest, QuicLegacyCodepointDisabled) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  ASSERT_TRUE(CreateClientAndServer());
  uint8_t kClientParams[] = {1, 2, 3, 4};
  uint8_t kServerParams[] = {5, 6, 7};
  SSL_set_quic_use_legacy_codepoint(client_.get(), 0);
  SSL_set_quic_use_legacy_codepoint(server_.get(), 0);
  ASSERT_TRUE(SSL_set_quic_transport_params(client_.get(), kClientParams,
                                            sizeof(kClientParams)));
  ASSERT_TRUE(SSL_set_quic_transport_params(server_.get(), kServerParams,
                                            sizeof(kServerParams)));

  ASSERT_TRUE(CompleteHandshakesForQUIC());
  ExpectReceivedTransportParamsEqual(client_.get(), kServerParams);
  ExpectReceivedTransportParamsEqual(server_.get(), kClientParams);
}

TEST_F(QUICMethodTest, QuicLegacyCodepointClientOnly) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  ASSERT_TRUE(CreateClientAndServer());
  uint8_t kClientParams[] = {1, 2, 3, 4};
  uint8_t kServerParams[] = {5, 6, 7};
  SSL_set_quic_use_legacy_codepoint(client_.get(), 1);
  SSL_set_quic_use_legacy_codepoint(server_.get(), 0);
  ASSERT_TRUE(SSL_set_quic_transport_params(client_.get(), kClientParams,
                                            sizeof(kClientParams)));
  ASSERT_TRUE(SSL_set_quic_transport_params(server_.get(), kServerParams,
                                            sizeof(kServerParams)));

  ASSERT_TRUE(RunQUICHandshakesAndExpectError(ExpectedError::kServerError));
}

TEST_F(QUICMethodTest, QuicLegacyCodepointServerOnly) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));

  ASSERT_TRUE(CreateClientAndServer());
  uint8_t kClientParams[] = {1, 2, 3, 4};
  uint8_t kServerParams[] = {5, 6, 7};
  SSL_set_quic_use_legacy_codepoint(client_.get(), 0);
  SSL_set_quic_use_legacy_codepoint(server_.get(), 1);
  ASSERT_TRUE(SSL_set_quic_transport_params(client_.get(), kClientParams,
                                            sizeof(kClientParams)));
  ASSERT_TRUE(SSL_set_quic_transport_params(server_.get(), kServerParams,
                                            sizeof(kServerParams)));

  ASSERT_TRUE(RunQUICHandshakesAndExpectError(ExpectedError::kServerError));
}

// Test that the default QUIC code point is consistent with
// |TLSEXT_TYPE_quic_transport_parameters|. This test ensures we remember to
// update the two values together.
TEST_F(QUICMethodTest, QuicCodePointDefault) {
  const SSL_QUIC_METHOD quic_method = DefaultQUICMethod();
  ASSERT_TRUE(SSL_CTX_set_quic_method(client_ctx_.get(), &quic_method));
  ASSERT_TRUE(SSL_CTX_set_quic_method(server_ctx_.get(), &quic_method));
  SSL_CTX_set_select_certificate_cb(
      server_ctx_.get(),
      [](const SSL_CLIENT_HELLO *client_hello) -> ssl_select_cert_result_t {
        const uint8_t *data;
        size_t len;
        if (!SSL_early_callback_ctx_extension_get(
                client_hello, TLSEXT_TYPE_quic_transport_parameters, &data,
                &len)) {
          ADD_FAILURE() << "Could not find quic_transport_parameters extension";
          return ssl_select_cert_error;
        }
        return ssl_select_cert_success;
      });

  ASSERT_TRUE(CreateClientAndServer());
  ASSERT_TRUE(CompleteHandshakesForQUIC());
}

extern "C" {
int BORINGSSL_enum_c_type_test(void);
}

TEST(SSLTest, EnumTypes) {
  EXPECT_EQ(sizeof(int), sizeof(ssl_private_key_result_t));
  EXPECT_EQ(1, BORINGSSL_enum_c_type_test());
}

TEST_P(SSLVersionTest, DoubleSSLError) {
  // Connect the inner SSL connections.
  ASSERT_TRUE(Connect());

  // Make a pair of |BIO|s which wrap |client_| and |server_|.
  UniquePtr<BIO_METHOD> bio_method(BIO_meth_new(0, nullptr));
  ASSERT_TRUE(bio_method);
  ASSERT_TRUE(BIO_meth_set_read(
      bio_method.get(), [](BIO *bio, char *out, int len) -> int {
        SSL *ssl = static_cast<SSL *>(BIO_get_data(bio));
        int ret = SSL_read(ssl, out, len);
        int ssl_ret = SSL_get_error(ssl, ret);
        if (ssl_ret == SSL_ERROR_WANT_READ) {
          BIO_set_retry_read(bio);
        }
        return ret;
      }));
  ASSERT_TRUE(BIO_meth_set_write(
      bio_method.get(), [](BIO *bio, const char *in, int len) -> int {
        SSL *ssl = static_cast<SSL *>(BIO_get_data(bio));
        int ret = SSL_write(ssl, in, len);
        int ssl_ret = SSL_get_error(ssl, ret);
        if (ssl_ret == SSL_ERROR_WANT_WRITE) {
          BIO_set_retry_write(bio);
        }
        return ret;
      }));
  ASSERT_TRUE(BIO_meth_set_ctrl(
      bio_method.get(), [](BIO *bio, int cmd, long larg, void *parg) -> long {
        // |SSL| objects require |BIO_flush| support.
        if (cmd == BIO_CTRL_FLUSH) {
          return 1;
        }
        return 0;
      }));

  UniquePtr<BIO> client_bio(BIO_new(bio_method.get()));
  ASSERT_TRUE(client_bio);
  BIO_set_data(client_bio.get(), client_.get());
  BIO_set_init(client_bio.get(), 1);

  UniquePtr<BIO> server_bio(BIO_new(bio_method.get()));
  ASSERT_TRUE(server_bio);
  BIO_set_data(server_bio.get(), server_.get());
  BIO_set_init(server_bio.get(), 1);

  // Wrap the inner connections in another layer of SSL.
  UniquePtr<SSL> client_outer(SSL_new(client_ctx_.get()));
  ASSERT_TRUE(client_outer);
  SSL_set_connect_state(client_outer.get());
  SSL_set_bio(client_outer.get(), client_bio.get(), client_bio.get());
  client_bio.release();  // |SSL_set_bio| takes ownership.

  UniquePtr<SSL> server_outer(SSL_new(server_ctx_.get()));
  ASSERT_TRUE(server_outer);
  SSL_set_accept_state(server_outer.get());
  SSL_set_bio(server_outer.get(), server_bio.get(), server_bio.get());
  server_bio.release();  // |SSL_set_bio| takes ownership.

  // Configure |client_outer| to reject the server certificate.
  SSL_set_custom_verify(
      client_outer.get(), SSL_VERIFY_PEER,
      [](SSL *ssl, uint8_t *out_alert) -> ssl_verify_result_t {
        return ssl_verify_invalid;
      });

  for (;;) {
    int client_ret = SSL_do_handshake(client_outer.get());
    int client_err = SSL_get_error(client_outer.get(), client_ret);
    if (client_err != SSL_ERROR_WANT_READ &&
        client_err != SSL_ERROR_WANT_WRITE) {
      // The client handshake should terminate on a certificate verification
      // error.
      EXPECT_EQ(SSL_ERROR_SSL, client_err);
      EXPECT_TRUE(ErrorEquals(ERR_peek_error(), ERR_LIB_SSL,
                              SSL_R_CERTIFICATE_VERIFY_FAILED));
      break;
    }

    // Run the server handshake and continue.
    int server_ret = SSL_do_handshake(server_outer.get());
    int server_err = SSL_get_error(server_outer.get(), server_ret);
    ASSERT_TRUE(server_err == SSL_ERROR_NONE ||
                server_err == SSL_ERROR_WANT_READ ||
                server_err == SSL_ERROR_WANT_WRITE);
  }
}

TEST_P(SSLVersionTest, SameKeyResume) {
  uint8_t key[48];
  RAND_bytes(key, sizeof(key));

  bssl::UniquePtr<SSL_CTX> server_ctx2 = CreateContext();
  ASSERT_TRUE(server_ctx2);
  ASSERT_TRUE(UseCertAndKey(server_ctx2.get()));
  ASSERT_TRUE(
      SSL_CTX_set_tlsext_ticket_keys(server_ctx_.get(), key, sizeof(key)));
  ASSERT_TRUE(
      SSL_CTX_set_tlsext_ticket_keys(server_ctx2.get(), key, sizeof(key)));

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx2.get(), SSL_SESS_CACHE_BOTH);

  // Establish a session for |server_ctx_|.
  bssl::UniquePtr<SSL_SESSION> session =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());
  ASSERT_TRUE(session);
  ClientConfig config;
  config.session = session.get();

  // No hits before we resume the connection
  EXPECT_EQ(SSL_CTX_sess_hits(client_ctx_.get()), 0);
  EXPECT_EQ(SSL_CTX_sess_hits(server_ctx_.get()), 0);
  EXPECT_EQ(SSL_CTX_sess_hits(server_ctx2.get()), 0);

  // Resuming with |server_ctx_| again works.
  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx_.get(),
                                     server_ctx_.get(), config));
  EXPECT_TRUE(SSL_session_reused(client.get()));
  EXPECT_TRUE(SSL_session_reused(server.get()));

  // Resuming with |server_ctx2| also works.
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx_.get(),
                                     server_ctx2.get(), config));
  EXPECT_TRUE(SSL_session_reused(client.get()));
  EXPECT_TRUE(SSL_session_reused(server.get()));

  // By this point, the session has been resumed twice on the client side and
  // once for each server context.
  EXPECT_EQ(SSL_CTX_sess_hits(client_ctx_.get()), 2);
  EXPECT_EQ(SSL_CTX_sess_hits(server_ctx_.get()), 1);
  EXPECT_EQ(SSL_CTX_sess_hits(server_ctx2.get()), 1);
}

TEST_P(SSLVersionTest, DifferentKeyNoResume) {
  uint8_t key1[48], key2[48];
  RAND_bytes(key1, sizeof(key1));
  RAND_bytes(key2, sizeof(key2));

  bssl::UniquePtr<SSL_CTX> server_ctx2 = CreateContext();
  ASSERT_TRUE(server_ctx2);
  ASSERT_TRUE(UseCertAndKey(server_ctx2.get()));
  ASSERT_TRUE(
      SSL_CTX_set_tlsext_ticket_keys(server_ctx_.get(), key1, sizeof(key1)));
  ASSERT_TRUE(
      SSL_CTX_set_tlsext_ticket_keys(server_ctx2.get(), key2, sizeof(key2)));

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx2.get(), SSL_SESS_CACHE_BOTH);

  // Establish a session for |server_ctx_|.
  bssl::UniquePtr<SSL_SESSION> session =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());
  ASSERT_TRUE(session);
  ClientConfig config;
  config.session = session.get();

  // Resuming with |server_ctx_| again works.
  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx_.get(),
                                     server_ctx_.get(), config));
  EXPECT_TRUE(SSL_session_reused(client.get()));
  EXPECT_TRUE(SSL_session_reused(server.get()));

  // Resuming with |server_ctx2| does not work.
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx_.get(),
                                     server_ctx2.get(), config));
  EXPECT_FALSE(SSL_session_reused(client.get()));
  EXPECT_FALSE(SSL_session_reused(server.get()));
}

TEST_P(SSLVersionTest, UnrelatedServerNoResume) {
  bssl::UniquePtr<SSL_CTX> server_ctx2 = CreateContext();
  ASSERT_TRUE(server_ctx2);
  ASSERT_TRUE(UseCertAndKey(server_ctx2.get()));

  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx2.get(), SSL_SESS_CACHE_BOTH);

  // Establish a session for |server_ctx_|.
  bssl::UniquePtr<SSL_SESSION> session =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());
  ASSERT_TRUE(session);
  ClientConfig config;
  config.session = session.get();

  // Resuming with |server_ctx_| again works.
  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx_.get(),
                                     server_ctx_.get(), config));
  EXPECT_TRUE(SSL_session_reused(client.get()));
  EXPECT_TRUE(SSL_session_reused(server.get()));

  // Resuming with |server_ctx2| does not work.
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx_.get(),
                                     server_ctx2.get(), config));
  EXPECT_FALSE(SSL_session_reused(client.get()));
  EXPECT_FALSE(SSL_session_reused(server.get()));
}

Span<const uint8_t> SessionIDOf(const SSL *ssl) {
  const SSL_SESSION *session = SSL_get_session(ssl);
  unsigned len;
  const uint8_t *data = SSL_SESSION_get_id(session, &len);
  return MakeConstSpan(data, len);
}

TEST_P(SSLVersionTest, TicketSessionIDsMatch) {
  // This checks that the session IDs at client and server match after a ticket
  // resumption. It's unclear whether this should be true, but Envoy depends
  // on it in their tests so this will give an early signal if we break it.
  SSL_CTX_set_session_cache_mode(client_ctx_.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx_.get(), SSL_SESS_CACHE_BOTH);

  bssl::UniquePtr<SSL_SESSION> session =
      CreateClientSession(client_ctx_.get(), server_ctx_.get());

  bssl::UniquePtr<SSL> client, server;
  ClientConfig config;
  config.session = session.get();
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx_.get(),
                                     server_ctx_.get(), config));
  EXPECT_TRUE(SSL_session_reused(client.get()));
  EXPECT_TRUE(SSL_session_reused(server.get()));

  EXPECT_EQ(Bytes(SessionIDOf(client.get())), Bytes(SessionIDOf(server.get())));
}

TEST_P(SSLVersionTest, PeerTmpKey) {
  if (getVersionParam().transfer_ssl) {
    // The peer's temporary key is not within the boundary of the SSL transfer
    // feature.
    GTEST_SKIP();
  }

  // Default should be using X5519 as the key exchange.
  ASSERT_TRUE(Connect());
  for (SSL *ssl : {client_.get(), server_.get()}) {
    SCOPED_TRACE(SSL_is_server(ssl) ? "server" : "client");
    EVP_PKEY *key = nullptr;
    EXPECT_TRUE(SSL_get_peer_tmp_key(ssl, &key));
    EXPECT_EQ(EVP_PKEY_id(key), EVP_PKEY_X25519);
    bssl::UniquePtr<EVP_PKEY> pkey(key);
  }

  // Check that EC Groups for the key exchange also work.
  ASSERT_TRUE(SSL_CTX_set1_groups_list(server_ctx_.get(), "P-384"));
  ASSERT_TRUE(Connect());
  for (SSL *ssl : {client_.get(), server_.get()}) {
    SCOPED_TRACE(SSL_is_server(ssl) ? "server" : "client");
    EVP_PKEY *key = nullptr;
    EXPECT_TRUE(SSL_get_peer_tmp_key(ssl, &key));
    EXPECT_EQ(EVP_PKEY_id(key), EVP_PKEY_EC);
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(key);
    EXPECT_TRUE(ec_key);
    EXPECT_EQ(EC_KEY_get0_group(ec_key), EC_group_p384());
    bssl::UniquePtr<EVP_PKEY> pkey(key);
  }
}

TEST_P(SSLVersionTest, GetFinished) {
  // Test that contents of |finished| and the peer's |finished| align.
  ASSERT_TRUE(Connect());
  for (SSL *ssl : {client_.get(), server_.get()}) {
    SCOPED_TRACE(SSL_is_server(ssl) ? "server" : "client");
    size_t finished_size = SSL_get_finished(ssl, nullptr, 0);
    EXPECT_TRUE(finished_size);
    bssl::UniquePtr<uint8_t> finished((uint8_t *)OPENSSL_malloc(finished_size));
    ASSERT_TRUE(finished);
    EXPECT_TRUE(SSL_get_finished(ssl, finished.get(), finished_size));

    size_t peer_finished_size = SSL_get_peer_finished(ssl, nullptr, 0);
    EXPECT_TRUE(peer_finished_size);
    bssl::UniquePtr<uint8_t> peer_finished(
        (uint8_t *)OPENSSL_malloc(peer_finished_size));
    ASSERT_TRUE(peer_finished);
    EXPECT_TRUE(SSL_get_finished(ssl, peer_finished.get(), peer_finished_size));

    EXPECT_EQ(Bytes(finished.get(), finished_size),
              Bytes(peer_finished.get(), peer_finished_size));
  }
}

static void WriteHelloRequest(SSL *server) {
  // This function assumes TLS 1.2 with ChaCha20-Poly1305.
  ASSERT_EQ(SSL_version(server), TLS1_2_VERSION);
  ASSERT_EQ(SSL_CIPHER_get_cipher_nid(SSL_get_current_cipher(server)),
            NID_chacha20_poly1305);

  // Encrypt a HelloRequest.
  uint8_t in[] = {SSL3_MT_HELLO_REQUEST, 0, 0, 0};
#if defined(BORINGSSL_UNSAFE_FUZZER_MODE)
  // Fuzzer-mode records are unencrypted.
  uint8_t record[5 + sizeof(in)];
  record[0] = SSL3_RT_HANDSHAKE;
  record[1] = 3;
  record[2] = 3;  // TLS 1.2
  record[3] = 0;
  record[4] = sizeof(record) - 5;
  memcpy(record + 5, in, sizeof(in));
#else
  // Extract key material from |server|.
  static const size_t kKeyLen = 32;
  static const size_t kNonceLen = 12;
  ASSERT_EQ(2u * (kKeyLen + kNonceLen), SSL_get_key_block_len(server));
  uint8_t key_block[2u * (kKeyLen + kNonceLen)];
  ASSERT_TRUE(SSL_generate_key_block(server, key_block, sizeof(key_block)));
  Span<uint8_t> key = MakeSpan(key_block + kKeyLen, kKeyLen);
  Span<uint8_t> nonce =
      MakeSpan(key_block + kKeyLen + kKeyLen + kNonceLen, kNonceLen);

  uint8_t ad[13];
  uint64_t seq = SSL_get_write_sequence(server);
  for (size_t i = 0; i < 8; i++) {
    // The nonce is XORed with the sequence number.
    nonce[11 - i] ^= uint8_t(seq);
    ad[7 - i] = uint8_t(seq);
    seq >>= 8;
  }

  ad[8] = SSL3_RT_HANDSHAKE;
  ad[9] = 3;
  ad[10] = 3;  // TLS 1.2
  ad[11] = 0;
  ad[12] = sizeof(in);

  uint8_t record[5 + sizeof(in) + 16];
  record[0] = SSL3_RT_HANDSHAKE;
  record[1] = 3;
  record[2] = 3;  // TLS 1.2
  record[3] = 0;
  record[4] = sizeof(record) - 5;

  ScopedEVP_AEAD_CTX aead;
  ASSERT_TRUE(EVP_AEAD_CTX_init(aead.get(), EVP_aead_chacha20_poly1305(),
                                key.data(), key.size(),
                                EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr));
  size_t len;
  ASSERT_TRUE(EVP_AEAD_CTX_seal(aead.get(), record + 5, &len,
                                sizeof(record) - 5, nonce.data(), nonce.size(),
                                in, sizeof(in), ad, sizeof(ad)));
  ASSERT_EQ(sizeof(record) - 5, len);
#endif  // BORINGSSL_UNSAFE_FUZZER_MODE

  ASSERT_EQ(int(sizeof(record)),
            BIO_write(SSL_get_wbio(server), record, sizeof(record)));
}

TEST_P(SSLTest, WriteWhileExplicitRenegotiate) {
  bssl::UniquePtr<SSL_CTX> ctx(CreateContextWithTestCertificate(TLS_method()));
  ASSERT_TRUE(ctx);

  ASSERT_TRUE(SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(ctx.get(), TLS1_2_VERSION));
  ASSERT_TRUE(SSL_CTX_set_strict_cipher_list(
      ctx.get(), "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server, ctx.get(), ctx.get()));
  SSL_set_renegotiate_mode(client.get(), ssl_renegotiate_explicit);
  ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));

  if (GetParam().transfer_ssl) {
    // |server| is reset to hold the transferred SSL.
    TransferSSL(&server, ctx.get(), nullptr);
  }

  static const uint8_t kInput[] = {'h', 'e', 'l', 'l', 'o'};

  // Write "hello" until the buffer is full, so |client| has a pending write.
  size_t num_writes = 0;
  for (;;) {
    int ret = SSL_write(client.get(), kInput, sizeof(kInput));
    if (ret != int(sizeof(kInput))) {
      ASSERT_EQ(-1, ret);
      ASSERT_EQ(SSL_ERROR_WANT_WRITE, SSL_get_error(client.get(), ret));
      break;
    }
    num_writes++;
  }

  ASSERT_NO_FATAL_FAILURE(WriteHelloRequest(server.get()));

  // |SSL_read| should pick up the HelloRequest.
  uint8_t byte;
  ASSERT_EQ(-1, SSL_read(client.get(), &byte, 1));
  ASSERT_EQ(SSL_ERROR_WANT_RENEGOTIATE, SSL_get_error(client.get(), -1));

  // Drain the data from the |client|.
  uint8_t buf[sizeof(kInput)];
  for (size_t i = 0; i < num_writes; i++) {
    ASSERT_EQ(int(sizeof(buf)), SSL_read(server.get(), buf, sizeof(buf)));
    EXPECT_EQ(Bytes(buf), Bytes(kInput));
  }

  // |client| should be able to finish the pending write and continue to write,
  // despite the paused HelloRequest.
  ASSERT_EQ(int(sizeof(kInput)),
            SSL_write(client.get(), kInput, sizeof(kInput)));
  ASSERT_EQ(int(sizeof(buf)), SSL_read(server.get(), buf, sizeof(buf)));
  EXPECT_EQ(Bytes(buf), Bytes(kInput));

  ASSERT_EQ(int(sizeof(kInput)),
            SSL_write(client.get(), kInput, sizeof(kInput)));
  ASSERT_EQ(int(sizeof(buf)), SSL_read(server.get(), buf, sizeof(buf)));
  EXPECT_EQ(Bytes(buf), Bytes(kInput));

  // |SSL_read| is stuck until we acknowledge the HelloRequest.
  ASSERT_EQ(-1, SSL_read(client.get(), &byte, 1));
  ASSERT_EQ(SSL_ERROR_WANT_RENEGOTIATE, SSL_get_error(client.get(), -1));

  ASSERT_TRUE(SSL_renegotiate(client.get()));
  ASSERT_EQ(-1, SSL_read(client.get(), &byte, 1));
  ASSERT_EQ(SSL_ERROR_WANT_READ, SSL_get_error(client.get(), -1));

  // We never renegotiate as a server.
  ASSERT_EQ(-1, SSL_read(server.get(), buf, sizeof(buf)));
  ASSERT_EQ(SSL_ERROR_SSL, SSL_get_error(server.get(), -1));
  EXPECT_TRUE(
      ErrorEquals(ERR_get_error(), ERR_LIB_SSL, SSL_R_NO_RENEGOTIATION));

  EXPECT_EQ(SSL_CTX_sess_connect_renegotiate(ctx.get()), 1);
  EXPECT_EQ(SSL_CTX_sess_accept_renegotiate(ctx.get()), 0);
}

TEST(SSLTest, ConnectionPropertiesDuringRenegotiate) {
  // Configure known connection properties, so we can check against them.
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  bssl::UniquePtr<X509> cert = GetTestCertificate();
  ASSERT_TRUE(cert);
  bssl::UniquePtr<EVP_PKEY> key = GetTestKey();
  ASSERT_TRUE(key);
  ASSERT_TRUE(SSL_CTX_use_certificate(ctx.get(), cert.get()));
  ASSERT_TRUE(SSL_CTX_use_PrivateKey(ctx.get(), key.get()));
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(ctx.get(), TLS1_2_VERSION));
  ASSERT_TRUE(SSL_CTX_set_strict_cipher_list(
      ctx.get(), "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"));
  ASSERT_TRUE(SSL_CTX_set1_groups_list(ctx.get(), "X25519"));
  ASSERT_TRUE(SSL_CTX_set1_sigalgs_list(ctx.get(), "rsa_pkcs1_sha256"));

  // Connect a client and server that accept renegotiation.
  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server, ctx.get(), ctx.get()));
  SSL_set_renegotiate_mode(client.get(), ssl_renegotiate_freely);
  ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));

  auto check_properties = [&] {
    EXPECT_EQ(SSL_version(client.get()), TLS1_2_VERSION);
    const SSL_CIPHER *cipher = SSL_get_current_cipher(client.get());
    ASSERT_TRUE(cipher);
    EXPECT_EQ(SSL_CIPHER_get_id(cipher),
              uint32_t{TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256});
    EXPECT_EQ(SSL_get_group_id(client.get()), SSL_GROUP_X25519);
    EXPECT_EQ(SSL_get_peer_signature_algorithm(client.get()),
              SSL_SIGN_RSA_PKCS1_SHA256);

    int psig_nid;
    EXPECT_TRUE(SSL_get_peer_signature_type_nid(client.get(), &psig_nid));
    EXPECT_EQ(psig_nid, EVP_PKEY_RSA);
    int digest_nid;
    EXPECT_TRUE(SSL_get_peer_signature_nid(client.get(), &digest_nid));
    EXPECT_EQ(digest_nid, NID_sha256);

    bssl::UniquePtr<X509> peer(SSL_get_peer_certificate(client.get()));
    ASSERT_TRUE(peer);
    EXPECT_EQ(X509_cmp(cert.get(), peer.get()), 0);
  };
  check_properties();

  // Client has not signed any TLS messages yet
  EXPECT_FALSE(SSL_get_peer_signature_type_nid(server.get(), nullptr));
  EXPECT_FALSE(SSL_get_peer_signature_nid(server.get(), nullptr));

  // The server sends a HelloRequest.
  ASSERT_NO_FATAL_FAILURE(WriteHelloRequest(server.get()));

  // Reading from the client will consume the HelloRequest, start a
  // renegotiation, and then block on a ServerHello from the server.
  uint8_t byte;
  ASSERT_EQ(-1, SSL_read(client.get(), &byte, 1));
  ASSERT_EQ(SSL_ERROR_WANT_READ, SSL_get_error(client.get(), -1));

  // Connection properties should continue to report values from the original
  // handshake.
  check_properties();
  EXPECT_EQ(SSL_CTX_sess_connect_renegotiate(ctx.get()), 1);
  EXPECT_EQ(SSL_CTX_sess_accept_renegotiate(ctx.get()), 0);

  // Client does not sign any messages in renegotiation either
  EXPECT_FALSE(SSL_get_peer_signature_type_nid(server.get(), nullptr));
  EXPECT_FALSE(SSL_get_peer_signature_nid(server.get(), nullptr));
}

TEST(SSLTest, SSLGetSignatureData) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  bssl::UniquePtr<X509> cert = GetECDSATestCertificate();
  ASSERT_TRUE(cert);
  bssl::UniquePtr<EVP_PKEY> key = GetECDSATestKey();
  ASSERT_TRUE(key);
  ASSERT_TRUE(SSL_CTX_use_certificate(ctx.get(), cert.get()));
  ASSERT_TRUE(SSL_CTX_use_PrivateKey(ctx.get(), key.get()));

  // Explicitly configure |SSL_VERIFY_PEER| so both the client and server
  // verify each other
  SSL_CTX_set_custom_verify(
          ctx.get(), SSL_VERIFY_PEER,
          [](SSL *ssl, uint8_t *out_alert) { return ssl_verify_ok; });

  ASSERT_TRUE(SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set1_sigalgs_list(ctx.get(), "ECDSA+SHA256"));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server, ctx.get(), ctx.get()));

  // Before handshake, neither client nor server has signed any messages
  ASSERT_FALSE(SSL_get_peer_signature_nid(client.get(), nullptr));
  ASSERT_FALSE(SSL_get_peer_signature_nid(server.get(), nullptr));
  ASSERT_FALSE(SSL_get_peer_signature_type_nid(client.get(), nullptr));
  ASSERT_FALSE(SSL_get_peer_signature_type_nid(server.get(), nullptr));

  ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));

  // Both client and server verified each other, both have signed TLS messages
  // now
  int client_digest, client_sigtype;
  ASSERT_TRUE(SSL_get_peer_signature_nid(server.get(), &client_digest));
  ASSERT_TRUE(SSL_get_peer_signature_type_nid(server.get(), &client_sigtype));
  ASSERT_EQ(client_sigtype, EVP_PKEY_EC);
  ASSERT_EQ(client_digest, NID_sha256);

  int server_digest, server_sigtype;
  ASSERT_TRUE(SSL_get_peer_signature_nid(client.get(), &server_digest));
  ASSERT_TRUE(SSL_get_peer_signature_type_nid(client.get(), &server_sigtype));
  ASSERT_EQ(server_sigtype, EVP_PKEY_EC);
  ASSERT_EQ(server_digest, NID_sha256);
}

TEST(SSLTest, CopyWithoutEarlyData) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx(
      CreateContextWithTestCertificate(TLS_method()));
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  SSL_CTX_set_session_cache_mode(client_ctx.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_session_cache_mode(server_ctx.get(), SSL_SESS_CACHE_BOTH);
  SSL_CTX_set_early_data_enabled(client_ctx.get(), 1);
  SSL_CTX_set_early_data_enabled(server_ctx.get(), 1);

  bssl::UniquePtr<SSL_SESSION> session =
      CreateClientSession(client_ctx.get(), server_ctx.get());
  ASSERT_TRUE(session);

  // The client should attempt early data with |session|.
  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(),
                                    server_ctx.get()));
  SSL_set_session(client.get(), session.get());
  SSL_set_early_data_enabled(client.get(), 1);
  ASSERT_EQ(1, SSL_do_handshake(client.get()));
  EXPECT_TRUE(SSL_in_early_data(client.get()));

  // |SSL_SESSION_copy_without_early_data| should disable early data but
  // still resume the session.
  bssl::UniquePtr<SSL_SESSION> session2(
      SSL_SESSION_copy_without_early_data(session.get()));
  ASSERT_TRUE(session2);
  EXPECT_NE(session.get(), session2.get());
  ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(),
                                    server_ctx.get()));
  SSL_set_session(client.get(), session2.get());
  SSL_set_early_data_enabled(client.get(), 1);
  EXPECT_TRUE(CompleteHandshakes(client.get(), server.get()));
  EXPECT_TRUE(SSL_session_reused(client.get()));
  EXPECT_EQ(ssl_early_data_unsupported_for_session,
            SSL_get_early_data_reason(client.get()));

  // |SSL_SESSION_copy_without_early_data| should be a reference count increase
  // when passed an early-data-incapable session.
  bssl::UniquePtr<SSL_SESSION> session3(
      SSL_SESSION_copy_without_early_data(session2.get()));
  EXPECT_EQ(session2.get(), session3.get());
}

TEST(SSLTest, ProcessTLS13NewSessionTicket) {
  // Configure client and server to negotiate TLS 1.3 only.
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx(
      CreateContextWithTestCertificate(TLS_method()));
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(server_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_3_VERSION));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));
  EXPECT_EQ(TLS1_3_VERSION, SSL_version(client.get()));

  // Process a TLS 1.3 NewSessionTicket.
  static const uint8_t kTicket[] = {
      0x04, 0x00, 0x00, 0xb2, 0x00, 0x02, 0xa3, 0x00, 0x04, 0x03, 0x02, 0x01,
      0x01, 0x00, 0x00, 0xa0, 0x01, 0x06, 0x09, 0x11, 0x16, 0x19, 0x21, 0x26,
      0x29, 0x31, 0x36, 0x39, 0x41, 0x46, 0x49, 0x51, 0x03, 0x06, 0x09, 0x13,
      0x16, 0x19, 0x23, 0x26, 0x29, 0x33, 0x36, 0x39, 0x43, 0x46, 0x49, 0x53,
      0xf7, 0x00, 0x29, 0xec, 0xf2, 0xc4, 0xa4, 0x41, 0xfc, 0x30, 0x17, 0x2e,
      0x9f, 0x7c, 0xa8, 0xaf, 0x75, 0x70, 0xf0, 0x1f, 0xc7, 0x98, 0xf7, 0xcf,
      0x5a, 0x5a, 0x6b, 0x5b, 0xfe, 0xf1, 0xe7, 0x3a, 0xe8, 0xf7, 0x6c, 0xd2,
      0xa8, 0xa6, 0x92, 0x5b, 0x96, 0x8d, 0xde, 0xdb, 0xd3, 0x20, 0x6a, 0xcb,
      0x69, 0x06, 0xf4, 0x91, 0x85, 0x2e, 0xe6, 0x5e, 0x0c, 0x59, 0xf2, 0x9e,
      0x9b, 0x79, 0x91, 0x24, 0x7e, 0x4a, 0x32, 0x3d, 0xbe, 0x4b, 0x80, 0x70,
      0xaf, 0xd0, 0x1d, 0xe2, 0xca, 0x05, 0x35, 0x09, 0x09, 0x05, 0x0f, 0xbb,
      0xc4, 0xae, 0xd7, 0xc4, 0xed, 0xd7, 0xae, 0x35, 0xc8, 0x73, 0x63, 0x78,
      0x64, 0xc9, 0x7a, 0x1f, 0xed, 0x7a, 0x9a, 0x47, 0x44, 0xfd, 0x50, 0xf7,
      0xb7, 0xe0, 0x64, 0xa9, 0x02, 0xc1, 0x5c, 0x23, 0x18, 0x3f, 0xc4, 0xcf,
      0x72, 0x02, 0x59, 0x2d, 0xe1, 0xaa, 0x61, 0x72, 0x00, 0x04, 0x5a, 0x5a,
      0x00, 0x00,
  };
  bssl::UniquePtr<SSL_SESSION> session(SSL_process_tls13_new_session_ticket(
      client.get(), kTicket, sizeof(kTicket)));
  ASSERT_TRUE(session);
  ASSERT_TRUE(SSL_SESSION_has_ticket(session.get()));

  uint8_t *session_buf = nullptr;
  size_t session_length = 0;
  ASSERT_TRUE(
      SSL_SESSION_to_bytes(session.get(), &session_buf, &session_length));
  bssl::UniquePtr<uint8_t> session_buf_free(session_buf);
  ASSERT_TRUE(session_buf);
  ASSERT_GT(session_length, 0u);

  // Servers cannot call |SSL_process_tls13_new_session_ticket|.
  ASSERT_FALSE(SSL_process_tls13_new_session_ticket(server.get(), kTicket,
                                                    sizeof(kTicket)));

  // Clients cannot call |SSL_process_tls13_new_session_ticket| before the
  // handshake completes.
  bssl::UniquePtr<SSL> client2(SSL_new(client_ctx.get()));
  ASSERT_TRUE(client2);
  SSL_set_connect_state(client2.get());
  ASSERT_FALSE(SSL_process_tls13_new_session_ticket(client2.get(), kTicket,
                                                    sizeof(kTicket)));
}

TEST(SSLTest, BIO) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx(
      CreateContextWithTestCertificate(TLS_method()));
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  for (bool take_ownership : {true, false}) {
    // For simplicity, get the handshake out of the way first.
    bssl::UniquePtr<SSL> client, server;
    ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                       server_ctx.get()));

    // Wrap |client| in an SSL BIO.
    bssl::UniquePtr<BIO> client_bio(BIO_new(BIO_f_ssl()));
    ASSERT_TRUE(client_bio);
    ASSERT_EQ(1, BIO_set_ssl(client_bio.get(), client.get(), take_ownership));
    if (take_ownership) {
      client.release();
    }

    // Flushing the BIO should not crash.
    EXPECT_EQ(1, BIO_flush(client_bio.get()));

    // Exchange some data.
    EXPECT_EQ(5, BIO_write(client_bio.get(), "hello", 5));
    uint8_t buf[5];
    ASSERT_EQ(5, SSL_read(server.get(), buf, sizeof(buf)));
    EXPECT_EQ(Bytes("hello"), Bytes(buf));

    EXPECT_EQ(5, SSL_write(server.get(), "world", 5));
    ASSERT_EQ(5, BIO_read(client_bio.get(), buf, sizeof(buf)));
    EXPECT_EQ(Bytes("world"), Bytes(buf));

    // |BIO_should_read| should work.
    EXPECT_EQ(-1, BIO_read(client_bio.get(), buf, sizeof(buf)));
    EXPECT_TRUE(BIO_should_read(client_bio.get()));

    // Writing data should eventually exceed the buffer size and fail, reporting
    // |BIO_should_write|.
    int ret;
    for (int i = 0; i < 1024; i++) {
      const uint8_t kZeros[1024] = {0};
      ret = BIO_write(client_bio.get(), kZeros, sizeof(kZeros));
      if (ret <= 0) {
        break;
      }
    }
    EXPECT_EQ(-1, ret);
    EXPECT_TRUE(BIO_should_write(client_bio.get()));
  }
}

TEST(SSLTest, BIO_2) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx(
      CreateContextWithTestCertificate(TLS_method()));
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);

  bssl::UniquePtr<BIO> server_bio(BIO_new_ssl(server_ctx.get(), 0));
  bssl::UniquePtr<BIO> client_bio(BIO_new_ssl_connect(client_ctx.get()));
  ASSERT_TRUE(server_bio);
  ASSERT_TRUE(client_bio);

  SSL *server_ssl_ptr, *client_ssl_ptr;
  ASSERT_TRUE(BIO_get_ssl(server_bio.get(), &server_ssl_ptr));
  ASSERT_TRUE(BIO_get_ssl(client_bio.get(), &client_ssl_ptr));
  ASSERT_TRUE(server_ssl_ptr);
  ASSERT_TRUE(client_ssl_ptr);

  // Client SSL BIOs typically establish connections to a host using
  // |BIO_do_connect|, which leverages the underlying connect |BIO| for socket
  // management. While OpenSSL provides |BIO_new_accept| and |BIO_s_accept| for
  // server-side socket setup, we haven't yet implemented this functionality.
  // For these tests, we opt for traditional SSL connection methods instead
  // until we have support for server-side socket management via |BIO|s.
  // Adding full socket management on the server side would exceed the scope of
  // testing |BIO_new_ssl(_connect)|, especially since we have dedicated tests
  // elsewhere that verify |BIO_do_connect|'s correctness.
  BIO *bio1, *bio2;
  ASSERT_TRUE(BIO_new_bio_pair(&bio1, 0, &bio2, 0));
  SSL_set_bio(client_ssl_ptr, bio1, bio1);
  SSL_set_bio(server_ssl_ptr, bio2, bio2);
  ASSERT_TRUE(CompleteHandshakes(client_ssl_ptr, server_ssl_ptr));
}

TEST(SSLTest, ALPNConfig) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  bssl::UniquePtr<X509> cert = GetTestCertificate();
  bssl::UniquePtr<EVP_PKEY> key = GetTestKey();
  ASSERT_TRUE(cert);
  ASSERT_TRUE(key);
  ASSERT_TRUE(SSL_CTX_use_certificate(ctx.get(), cert.get()));
  ASSERT_TRUE(SSL_CTX_use_PrivateKey(ctx.get(), key.get()));

  // Set up some machinery to check the configured ALPN against what is actually
  // sent over the wire. Note that the ALPN callback is only called when the
  // client offers ALPN.
  std::vector<uint8_t> observed_alpn;
  SSL_CTX_set_alpn_select_cb(
      ctx.get(),
      [](SSL *ssl, const uint8_t **out, uint8_t *out_len, const uint8_t *in,
         unsigned in_len, void *arg) -> int {
        std::vector<uint8_t> *observed_alpn_ptr =
            static_cast<std::vector<uint8_t> *>(arg);
        observed_alpn_ptr->assign(in, in + in_len);
        return SSL_TLSEXT_ERR_NOACK;
      },
      &observed_alpn);
  auto check_alpn_proto = [&](Span<const uint8_t> expected) {
    observed_alpn.clear();
    bssl::UniquePtr<SSL> client, server;
    ASSERT_TRUE(ConnectClientAndServer(&client, &server, ctx.get(), ctx.get()));
    EXPECT_EQ(Bytes(expected), Bytes(observed_alpn));
  };

  // Note that |SSL_CTX_set_alpn_protos|'s return value is reversed.
  static const uint8_t kValidList[] = {0x03, 'f', 'o', 'o',
                                       0x03, 'b', 'a', 'r'};
  EXPECT_EQ(0,
            SSL_CTX_set_alpn_protos(ctx.get(), kValidList, sizeof(kValidList)));
  check_alpn_proto(kValidList);

  // Invalid lists are rejected.
  static const uint8_t kInvalidList[] = {0x04, 'f', 'o', 'o'};
  EXPECT_EQ(1, SSL_CTX_set_alpn_protos(ctx.get(), kInvalidList,
                                       sizeof(kInvalidList)));

  // Empty lists are valid and are interpreted as disabling ALPN.
  EXPECT_EQ(0, SSL_CTX_set_alpn_protos(ctx.get(), nullptr, 0));
  check_alpn_proto({});
}

// This is a basic unit-test class to verify completing handshake successfully,
// sending the correct codepoint extension and having correct application
// setting on different combination of ALPS codepoint settings. More integration
// tests on runner.go.
class AlpsNewCodepointTest : public testing::Test {
 protected:
  void SetUp() override {
    client_ctx_.reset(SSL_CTX_new(TLS_method()));
    server_ctx_ = CreateContextWithTestCertificate(TLS_method());
    ASSERT_TRUE(client_ctx_);
    ASSERT_TRUE(server_ctx_);
  }

  void SetUpApplicationSetting() {
    static const uint8_t alpn[] = {0x03, 'f', 'o', 'o'};
    static const uint8_t proto[] = {'f', 'o', 'o'};
    static const uint8_t alps[] = {0x04, 'a', 'l', 'p', 's'};
    // SSL_set_alpn_protos's return value is backwards. It returns zero on
    // success and one on failure.
    ASSERT_FALSE(SSL_set_alpn_protos(client_.get(), alpn, sizeof(alpn)));
    SSL_CTX_set_alpn_select_cb(
      server_ctx_.get(),
      [](SSL *ssl, const uint8_t **out, uint8_t *out_len, const uint8_t *in,
          unsigned in_len, void *arg) -> int {
        return SSL_select_next_proto(
                    const_cast<uint8_t **>(out), out_len, in, in_len,
                    alpn, sizeof(alpn)) == OPENSSL_NPN_NEGOTIATED
                    ? SSL_TLSEXT_ERR_OK
                    : SSL_TLSEXT_ERR_NOACK;
      },
      nullptr);
    ASSERT_TRUE(SSL_add_application_settings(client_.get(), proto,
                                            sizeof(proto), nullptr, 0));
    ASSERT_TRUE(SSL_add_application_settings(server_.get(), proto,
                                            sizeof(proto), alps, sizeof(alps)));
  }

  bssl::UniquePtr<SSL_CTX> client_ctx_;
  bssl::UniquePtr<SSL_CTX> server_ctx_;

  bssl::UniquePtr<SSL> client_;
  bssl::UniquePtr<SSL> server_;
};

TEST_F(AlpsNewCodepointTest, Enabled) {
  SetUpExpectedNewCodePoint(server_ctx_.get());

  ASSERT_TRUE(CreateClientAndServer(&client_, &server_, client_ctx_.get(),
                                    server_ctx_.get()));

  SSL_set_alps_use_new_codepoint(client_.get(), 1);
  SSL_set_alps_use_new_codepoint(server_.get(), 1);

  SetUpApplicationSetting();
  ASSERT_TRUE(CompleteHandshakes(client_.get(), server_.get()));
  ASSERT_TRUE(SSL_has_application_settings(client_.get()));
}

TEST_F(AlpsNewCodepointTest, Disabled) {
  // Both client and server disable alps new codepoint.
  SetUpExpectedOldCodePoint(server_ctx_.get());

  ASSERT_TRUE(CreateClientAndServer(&client_, &server_, client_ctx_.get(),
                                    server_ctx_.get()));

  SSL_set_alps_use_new_codepoint(client_.get(), 0);
  SSL_set_alps_use_new_codepoint(server_.get(), 0);

  SetUpApplicationSetting();
  ASSERT_TRUE(CompleteHandshakes(client_.get(), server_.get()));
  ASSERT_TRUE(SSL_has_application_settings(client_.get()));
}

TEST_F(AlpsNewCodepointTest, ClientOnly) {
  // If client set new codepoint but server doesn't set, server ignores it.
  SetUpExpectedNewCodePoint(server_ctx_.get());

  ASSERT_TRUE(CreateClientAndServer(&client_, &server_, client_ctx_.get(),
                                    server_ctx_.get()));

  SSL_set_alps_use_new_codepoint(client_.get(), 1);
  SSL_set_alps_use_new_codepoint(server_.get(), 0);

  SetUpApplicationSetting();
  ASSERT_TRUE(CompleteHandshakes(client_.get(), server_.get()));
  ASSERT_FALSE(SSL_has_application_settings(client_.get()));
}

TEST_F(AlpsNewCodepointTest, ServerOnly) {
  // If client doesn't set new codepoint, while server set.
  SetUpExpectedOldCodePoint(server_ctx_.get());

  ASSERT_TRUE(CreateClientAndServer(&client_, &server_, client_ctx_.get(),
                                    server_ctx_.get()));

  SSL_set_alps_use_new_codepoint(client_.get(), 0);
  SSL_set_alps_use_new_codepoint(server_.get(), 1);

  SetUpApplicationSetting();
  ASSERT_TRUE(CompleteHandshakes(client_.get(), server_.get()));
  ASSERT_FALSE(SSL_has_application_settings(client_.get()));
}

// Test that the key usage checker can correctly handle issuerUID and
// subjectUID. See https://crbug.com/1199744.
TEST(SSLTest, KeyUsageWithUIDs) {
  static const char kGoodKeyUsage[] = R"(
-----BEGIN CERTIFICATE-----
MIIB7DCCAZOgAwIBAgIJANlMBNpJfb/rMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQwHhcNMTQwNDIzMjMyMTU3WhcNMTQwNTIzMjMyMTU3WjBFMQsw
CQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu
ZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5itp
4r9ln5e+Lx4NlIpM1Zdrt6keDUb73ampHp3culoB59aXqAoY+cPEox5W4nyDSNsW
Ghz1HX7xlC1Lz3IiwYEEABI0VoIEABI0VqNgMF4wHQYDVR0OBBYEFKuE0qyrlfCC
ThZ4B1VXX+QmjYLRMB8GA1UdIwQYMBaAFKuE0qyrlfCCThZ4B1VXX+QmjYLRMA4G
A1UdDwEB/wQEAwIHgDAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIEWJ
34EcqW5MHwLIA1hZ2Tj/jV2QjN02KLxis9mFsqDKAiAMlMTkzsM51vVs9Ohqa+Rc
4Z7qDhjIhiF4dM0uEDYRVA==
-----END CERTIFICATE-----
)";
  static const char kBadKeyUsage[] = R"(
-----BEGIN CERTIFICATE-----
MIIB7jCCAZOgAwIBAgIJANlMBNpJfb/rMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQwHhcNMTQwNDIzMjMyMTU3WhcNMTQwNTIzMjMyMTU3WjBFMQsw
CQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu
ZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5itp
4r9ln5e+Lx4NlIpM1Zdrt6keDUb73ampHp3culoB59aXqAoY+cPEox5W4nyDSNsW
Ghz1HX7xlC1Lz3IiwYEEABI0VoIEABI0VqNgMF4wHQYDVR0OBBYEFKuE0qyrlfCC
ThZ4B1VXX+QmjYLRMB8GA1UdIwQYMBaAFKuE0qyrlfCCThZ4B1VXX+QmjYLRMA4G
A1UdDwEB/wQEAwIDCDAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQC6
taYBUDu2gcZC6EMk79FBHArYI0ucF+kzvETegZCbBAIhANtObFec5gtso/47moPD
RHrQbWsFUakETXL9QMlegh5t
-----END CERTIFICATE-----
)";

  bssl::UniquePtr<X509> good = CertFromPEM(kGoodKeyUsage);
  ASSERT_TRUE(good);
  bssl::UniquePtr<X509> bad = CertFromPEM(kBadKeyUsage);
  ASSERT_TRUE(bad);

  // We check key usage when configuring EC certificates to distinguish ECDSA
  // and ECDH.
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  EXPECT_TRUE(SSL_CTX_use_certificate(ctx.get(), good.get()));
  EXPECT_FALSE(SSL_CTX_use_certificate(ctx.get(), bad.get()));
}

// Test that |SSL_can_release_private_key| reports true as early as expected.
// The internal asserts in the library check we do not report true too early.
TEST(SSLTest, CanReleasePrivateKey) {
  bssl::UniquePtr<SSL_CTX> client_ctx =
      CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  SSL_CTX_set_session_cache_mode(client_ctx.get(), SSL_SESS_CACHE_BOTH);

  // Note this assumes the transport buffer is large enough to fit the client
  // and server first flights. We check this with |SSL_ERROR_WANT_READ|. If the
  // transport buffer was too small it would return |SSL_ERROR_WANT_WRITE|.
  auto check_first_server_round_trip = [&](SSL *client, SSL *server) {
    // Write the ClientHello.
    ASSERT_EQ(-1, SSL_do_handshake(client));
    ASSERT_EQ(SSL_ERROR_WANT_READ, SSL_get_error(client, -1));

    // Consume the ClientHello and write the server flight.
    ASSERT_EQ(-1, SSL_do_handshake(server));
    ASSERT_EQ(SSL_ERROR_WANT_READ, SSL_get_error(server, -1));

    EXPECT_TRUE(SSL_can_release_private_key(server));
  };

  {
    SCOPED_TRACE("TLS 1.2 ECDHE");
    bssl::UniquePtr<SSL_CTX> server_ctx(
        CreateContextWithTestCertificate(TLS_method()));
    ASSERT_TRUE(server_ctx);
    ASSERT_TRUE(
        SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_2_VERSION));
    ASSERT_TRUE(SSL_CTX_set_strict_cipher_list(
        server_ctx.get(), "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));
    // Configure the server to request client certificates, so we can also test
    // the client half.
    SSL_CTX_set_custom_verify(
        server_ctx.get(), SSL_VERIFY_PEER,
        [](SSL *ssl, uint8_t *out_alert) { return ssl_verify_ok; });
    bssl::UniquePtr<SSL> client, server;
    ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(),
                                      server_ctx.get()));
    check_first_server_round_trip(client.get(), server.get());

    // Consume the server flight and write the client response. The client still
    // has a Finished message to consume but can also release its key early.
    ASSERT_EQ(-1, SSL_do_handshake(client.get()));
    ASSERT_EQ(SSL_ERROR_WANT_READ, SSL_get_error(client.get(), -1));
    EXPECT_TRUE(SSL_can_release_private_key(client.get()));

    // However, a client that has not disabled renegotiation can never release
    // the key.
    ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(),
                                      server_ctx.get()));
    SSL_set_renegotiate_mode(client.get(), ssl_renegotiate_freely);
    check_first_server_round_trip(client.get(), server.get());
    ASSERT_EQ(-1, SSL_do_handshake(client.get()));
    ASSERT_EQ(SSL_ERROR_WANT_READ, SSL_get_error(client.get(), -1));
    EXPECT_FALSE(SSL_can_release_private_key(client.get()));
  }

  {
    SCOPED_TRACE("TLS 1.2 resumption");
    bssl::UniquePtr<SSL_CTX> server_ctx(
        CreateContextWithTestCertificate(TLS_method()));
    ASSERT_TRUE(server_ctx);
    ASSERT_TRUE(
        SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_2_VERSION));
    bssl::UniquePtr<SSL_SESSION> session =
        CreateClientSession(client_ctx.get(), server_ctx.get());
    ASSERT_TRUE(session);
    bssl::UniquePtr<SSL> client, server;
    ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(),
                                      server_ctx.get()));
    SSL_set_session(client.get(), session.get());
    check_first_server_round_trip(client.get(), server.get());
  }

  {
    SCOPED_TRACE("TLS 1.3 1-RTT");
    bssl::UniquePtr<SSL_CTX> server_ctx(
        CreateContextWithTestCertificate(TLS_method()));
    ASSERT_TRUE(server_ctx);
    ASSERT_TRUE(
        SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_3_VERSION));
    bssl::UniquePtr<SSL> client, server;
    ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(),
                                      server_ctx.get()));
    check_first_server_round_trip(client.get(), server.get());
  }

  {
    SCOPED_TRACE("TLS 1.3 resumption");
    bssl::UniquePtr<SSL_CTX> server_ctx(
        CreateContextWithTestCertificate(TLS_method()));
    ASSERT_TRUE(server_ctx);
    ASSERT_TRUE(
        SSL_CTX_set_max_proto_version(server_ctx.get(), TLS1_3_VERSION));
    bssl::UniquePtr<SSL_SESSION> session =
        CreateClientSession(client_ctx.get(), server_ctx.get());
    ASSERT_TRUE(session);
    bssl::UniquePtr<SSL> client, server;
    ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(),
                                      server_ctx.get()));
    SSL_set_session(client.get(), session.get());
    check_first_server_round_trip(client.get(), server.get());
  }
}

// GetExtensionOrder sets |*out| to the list of extensions a client attached to
// |ctx| will send in the ClientHello. If |ech_keys| is non-null, the client
// will offer ECH with the public component. If |decrypt_ech| is true, |*out|
// will be set to the ClientHelloInner's extensions, rather than
// ClientHelloOuter.
static bool GetExtensionOrder(SSL_CTX *client_ctx, std::vector<uint16_t> *out,
                              SSL_ECH_KEYS *ech_keys, bool decrypt_ech) {
  struct AppData {
    std::vector<uint16_t> *out;
    bool decrypt_ech;
    bool callback_done = false;
  };
  AppData app_data;
  app_data.out = out;
  app_data.decrypt_ech = decrypt_ech;

  bssl::UniquePtr<SSL_CTX> server_ctx =
      CreateContextWithTestCertificate(TLS_method());
  if (!server_ctx ||  //
      !SSL_CTX_set_app_data(server_ctx.get(), &app_data) ||
      (decrypt_ech && !SSL_CTX_set1_ech_keys(server_ctx.get(), ech_keys))) {
    return false;
  }

  // Configure the server to record the ClientHello extension order. We use a
  // server rather than |GetClientHello| so it can decrypt ClientHelloInner.
  SSL_CTX_set_select_certificate_cb(
      server_ctx.get(),
      [](const SSL_CLIENT_HELLO *client_hello) -> ssl_select_cert_result_t {
        AppData *app_data_ptr = static_cast<AppData *>(
            SSL_CTX_get_app_data(SSL_get_SSL_CTX(client_hello->ssl)));
        EXPECT_EQ(app_data_ptr->decrypt_ech ? 1 : 0,
                  SSL_ech_accepted(client_hello->ssl));

        app_data_ptr->out->clear();
        CBS extensions;
        CBS_init(&extensions, client_hello->extensions,
                 client_hello->extensions_len);
        while (CBS_len(&extensions)) {
          uint16_t type;
          CBS body;
          if (!CBS_get_u16(&extensions, &type) ||
              !CBS_get_u16_length_prefixed(&extensions, &body)) {
            return ssl_select_cert_error;
          }
          app_data_ptr->out->push_back(type);
        }

        // Don't bother completing the handshake.
        app_data_ptr->callback_done = true;
        return ssl_select_cert_error;
      });

  bssl::UniquePtr<SSL> client, server;
  if (!CreateClientAndServer(&client, &server, client_ctx, server_ctx.get()) ||
      (ech_keys != nullptr && !InstallECHConfigList(client.get(), ech_keys))) {
    return false;
  }

  // Run the handshake far enough to process the ClientHello.
  SSL_do_handshake(client.get());
  SSL_do_handshake(server.get());
  return app_data.callback_done;
}

// Test that, when extension permutation is enabled, the ClientHello extension
// order changes, both with and without ECH, and in both ClientHelloInner and
// ClientHelloOuter.
TEST(SSLTest, PermuteExtensions) {
  bssl::UniquePtr<SSL_ECH_KEYS> keys = MakeTestECHKeys();
  ASSERT_TRUE(keys);
  for (bool offer_ech : {false, true}) {
    SCOPED_TRACE(offer_ech);
    SSL_ECH_KEYS *maybe_keys = offer_ech ? keys.get() : nullptr;
    for (bool decrypt_ech : {false, true}) {
      SCOPED_TRACE(decrypt_ech);
      if (!offer_ech && decrypt_ech) {
        continue;
      }

      // When extension permutation is disabled, the order should be consistent.
      bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
      ASSERT_TRUE(ctx);
      std::vector<uint16_t> order1, order2;
      ASSERT_TRUE(
          GetExtensionOrder(ctx.get(), &order1, maybe_keys, decrypt_ech));
      ASSERT_TRUE(
          GetExtensionOrder(ctx.get(), &order2, maybe_keys, decrypt_ech));
      EXPECT_EQ(order1, order2);

      ctx.reset(SSL_CTX_new(TLS_method()));
      ASSERT_TRUE(ctx);
      SSL_CTX_set_permute_extensions(ctx.get(), 1);

      // When extension permutation is enabled, each ClientHello should have a
      // different order.
      //
      // This test is inherently flaky, so we run it multiple times. We send at
      // least five extensions by default from TLS 1.3: supported_versions,
      // key_share, supported_groups, psk_key_exchange_modes, and
      // signature_algorithms. That means the probability of a false negative is
      // at most 1/120. Repeating the test 14 times lowers false negative rate
      // to under 2^-96.
      ASSERT_TRUE(
          GetExtensionOrder(ctx.get(), &order1, maybe_keys, decrypt_ech));
      EXPECT_GE(order1.size(), 5u);
      static const int kNumIterations = 14;
      bool passed = false;
      for (int i = 0; i < kNumIterations; i++) {
        ASSERT_TRUE(
            GetExtensionOrder(ctx.get(), &order2, maybe_keys, decrypt_ech));
        if (order1 != order2) {
          passed = true;
          break;
        }
      }
      EXPECT_TRUE(passed) << "Extensions were not permuted";
    }
  }
}

TEST(SSLTest, HostMatching) {
  static const char kCertPEM[] = R"(
-----BEGIN CERTIFICATE-----
MIIB9jCCAZ2gAwIBAgIQeudG9R61BOxUvWkeVhU5DTAKBggqhkjOPQQDAjApMRAw
DgYDVQQKEwdBY21lIENvMRUwEwYDVQQDEwxleGFtcGxlMy5jb20wHhcNMjExMjA2
MjA1NjU2WhcNMjIxMjA2MjA1NjU2WjApMRAwDgYDVQQKEwdBY21lIENvMRUwEwYD
VQQDEwxleGFtcGxlMy5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS7l2VO
Bl2TjVm9WfGk24+hMbVFUNB+RVHWbCvFvNZAoWiIJ2z34RLGInyZvCZ8xLAvsuaW
ULDDaoeDl1M0t4Hmo4GmMIGjMA4GA1UdDwEB/wQEAwIChDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTTJWurcc1t+VPQBko3
Gsw6cbcWSTBMBgNVHREERTBDggxleGFtcGxlMS5jb22CDGV4YW1wbGUyLmNvbYIP
YSouZXhhbXBsZTQuY29tgg4qLmV4YW1wbGU1LmNvbYcEAQIDBDAKBggqhkjOPQQD
AgNHADBEAiAAv0ljHJGrgyzZDkG6XvNZ5ewxRfnXcZuD0Y7E4giCZgIgNK1qjilu
5DyVbfKeeJhOCtGxqE1dWLXyJBnoRomSYBY=
-----END CERTIFICATE-----
)";
  bssl::UniquePtr<X509> cert(CertFromPEM(kCertPEM));
  ASSERT_TRUE(cert);
  static const char kCertNoSANsPEM[] = R"(
-----BEGIN CERTIFICATE-----
MIIBqzCCAVGgAwIBAgIQeudG9R61BOxUvWkeVhU5DTAKBggqhkjOPQQDAjArMRIw
EAYDVQQKEwlBY21lIENvIDIxFTATBgNVBAMTDGV4YW1wbGUzLmNvbTAeFw0yMTEy
MDYyMDU2NTZaFw0yMjEyMDYyMDU2NTZaMCsxEjAQBgNVBAoTCUFjbWUgQ28gMjEV
MBMGA1UEAxMMZXhhbXBsZTMuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
u5dlTgZdk41ZvVnxpNuPoTG1RVDQfkVR1mwrxbzWQKFoiCds9+ESxiJ8mbwmfMSw
L7LmllCww2qHg5dTNLeB5qNXMFUwDgYDVR0PAQH/BAQDAgKEMBMGA1UdJQQMMAoG
CCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFNMla6txzW35U9AG
SjcazDpxtxZJMAoGCCqGSM49BAMCA0gAMEUCIG3YWGWtpVhbcGV7wFKQwTfmvwHW
pw4qCFZlool4hCwsAiEA+2fc6NfSbNpFEtQkDOMJW2ANiScAVEmImNqPfb2klz4=
-----END CERTIFICATE-----
)";
  bssl::UniquePtr<X509> cert_no_sans(CertFromPEM(kCertNoSANsPEM));
  ASSERT_TRUE(cert_no_sans);

  static const char kKeyPEM[] = R"(
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghsaSZhUzZAcQlLyJ
MDuy7WPdyqNsAX9rmEP650LF/q2hRANCAAS7l2VOBl2TjVm9WfGk24+hMbVFUNB+
RVHWbCvFvNZAoWiIJ2z34RLGInyZvCZ8xLAvsuaWULDDaoeDl1M0t4Hm
-----END PRIVATE KEY-----
)";
  bssl::UniquePtr<EVP_PKEY> key(KeyFromPEM(kKeyPEM));
  ASSERT_TRUE(key);

  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(X509_STORE_add_cert(SSL_CTX_get_cert_store(client_ctx.get()),
                                  cert.get()));
  ASSERT_TRUE(X509_STORE_add_cert(SSL_CTX_get_cert_store(client_ctx.get()),
                                  cert_no_sans.get()));
  SSL_CTX_set_verify(client_ctx.get(),
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     nullptr);
  X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(client_ctx.get()),
                              X509_V_FLAG_NO_CHECK_TIME);

  struct TestCase {
    X509 *cert;
    std::string hostname;
    unsigned flags;
    bool should_match;
  };
  std::vector<TestCase> kTests = {
      // These two names are present as SANs in the certificate.
      {cert.get(), "example1.com", 0, true},
      {cert.get(), "example2.com", 0, true},
      // This is the CN of the certificate, but that shouldn't matter if a SAN
      // extension is present.
      {cert.get(), "example3.com", 0, false},
      // If the SAN is not present, we, for now, look for DNS names in the CN.
      {cert_no_sans.get(), "example3.com", 0, true},
      // ... but this can be turned off.
      {cert_no_sans.get(), "example3.com", X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,
       false},
      // a*.example4.com is a SAN, but is invalid.
      {cert.get(), "abc.example4.com", 0, false},
      // *.example5.com is a SAN in the certificate, which is a normal and valid
      // wildcard.
      {cert.get(), "abc.example5.com", 0, true},
      // This name is not present.
      {cert.get(), "notexample1.com", 0, false},
      // The IPv4 address 1.2.3.4 is a SAN, but that shouldn't match against a
      // hostname that happens to be its textual representation.
      {cert.get(), "1.2.3.4", 0, false},
  };

  for (const TestCase &test : kTests) {
    SCOPED_TRACE(test.hostname);

    bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_method()));
    ASSERT_TRUE(server_ctx);
    ASSERT_TRUE(SSL_CTX_use_certificate(server_ctx.get(), test.cert));
    ASSERT_TRUE(SSL_CTX_use_PrivateKey(server_ctx.get(), key.get()));

    ClientConfig config;
    bssl::UniquePtr<SSL> client, server;
    config.verify_hostname = test.hostname;
    config.hostflags = test.flags;
    EXPECT_EQ(test.should_match,
              ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get(), config));
  }
}

TEST(SSLTest, NumTickets) {
  bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(server_ctx);
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(client_ctx);
  bssl::UniquePtr<X509> cert = GetTestCertificate();
  ASSERT_TRUE(cert);
  bssl::UniquePtr<EVP_PKEY> key = GetTestKey();
  ASSERT_TRUE(key);
  ASSERT_TRUE(SSL_CTX_use_certificate(server_ctx.get(), cert.get()));
  ASSERT_TRUE(SSL_CTX_use_PrivateKey(server_ctx.get(), key.get()));
  SSL_CTX_set_session_cache_mode(server_ctx.get(), SSL_SESS_CACHE_BOTH);

  SSL_CTX_set_session_cache_mode(client_ctx.get(), SSL_SESS_CACHE_BOTH);
  static size_t ticket_count;
  SSL_CTX_sess_set_new_cb(client_ctx.get(), [](SSL *, SSL_SESSION *) -> int {
    ticket_count++;
    return 0;
  });

  auto count_tickets = [&]() -> size_t {
    ticket_count = 0;
    bssl::UniquePtr<SSL> client, server;
    if (!ConnectClientAndServer(&client, &server, client_ctx.get(),
                                server_ctx.get()) ||
        !FlushNewSessionTickets(client.get(), server.get())) {
      ADD_FAILURE() << "Could not run handshake";
      return 0;
    }
    return ticket_count;
  };

  // By default, we should send two tickets.
  EXPECT_EQ(count_tickets(), 2u);

  for (size_t num_tickets : {0, 1, 2, 3, 4, 5}) {
    SCOPED_TRACE(num_tickets);
    ASSERT_TRUE(SSL_CTX_set_num_tickets(server_ctx.get(), num_tickets));
    EXPECT_EQ(SSL_CTX_get_num_tickets(server_ctx.get()), num_tickets);
    EXPECT_EQ(count_tickets(), num_tickets);
  }

  // Configuring too many tickets causes us to stop at some point.
  ASSERT_TRUE(SSL_CTX_set_num_tickets(server_ctx.get(), 100000));
  EXPECT_EQ(SSL_CTX_get_num_tickets(server_ctx.get()), 16u);
  EXPECT_EQ(count_tickets(), 16u);
}

TEST(SSLTest, CertSubjectsToStack) {
  const std::string kCert1 = R"(
-----BEGIN CERTIFICATE-----
MIIBzzCCAXagAwIBAgIJANlMBNpJfb/rMAkGByqGSM49BAEwRTELMAkGA1UEBhMC
QVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdp
dHMgUHR5IEx0ZDAeFw0xNDA0MjMyMzIxNTdaFw0xNDA1MjMyMzIxNTdaMEUxCzAJ
BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l
dCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATmK2ni
v2Wfl74vHg2UikzVl2u3qR4NRvvdqakendy6WgHn1peoChj5w8SjHlbifINI2xYa
HPUdfvGULUvPciLBo1AwTjAdBgNVHQ4EFgQUq4TSrKuV8IJOFngHVVdf5CaNgtEw
HwYDVR0jBBgwFoAUq4TSrKuV8IJOFngHVVdf5CaNgtEwDAYDVR0TBAUwAwEB/zAJ
BgcqhkjOPQQBA0gAMEUCIQDyoDVeUTo2w4J5m+4nUIWOcAZ0lVfSKXQA9L4Vh13E
BwIgfB55FGohg/B6dGh5XxSZmmi08cueFV7mHzJSYV51yRQ=
-----END CERTIFICATE-----
)";
  const std::vector<uint8_t> kName1 = {
      0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
      0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
      0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65,
      0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49,
      0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67,
      0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64};
  const std::string kCert2 = R"(
-----BEGIN CERTIFICATE-----
MIICXjCCAcegAwIBAgIIWjO48ufpunYwDQYJKoZIhvcNAQELBQAwNjEaMBgGA1UE
ChMRQm9yaW5nU1NMIFRFU1RJTkcxGDAWBgNVBAMTD0ludGVybWVkaWF0ZSBDQTAg
Fw0xNTAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowMjEaMBgGA1UEChMRQm9y
aW5nU1NMIFRFU1RJTkcxFDASBgNVBAMTC2V4YW1wbGUuY29tMIGfMA0GCSqGSIb3
DQEBAQUAA4GNADCBiQKBgQDD0U0ZYgqShJ7oOjsyNKyVXEHqeafmk/bAoPqY/h1c
oPw2E8KmeqiUSoTPjG5IXSblOxcqpbAXgnjPzo8DI3GNMhAf8SYNYsoH7gc7Uy7j
5x8bUrisGnuTHqkqH6d4/e7ETJ7i3CpR8bvK16DggEvQTudLipz8FBHtYhFakfdh
TwIDAQABo3cwdTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
CCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwGQYDVR0OBBIEEKN5pvbur7mlXjeMEYA0
4nUwGwYDVR0jBBQwEoAQjBpoqLV2211Xex+NFLIGozANBgkqhkiG9w0BAQsFAAOB
gQBj/p+JChp//LnXWC1k121LM/ii7hFzQzMrt70bny406SGz9jAjaPOX4S3gt38y
rhjpPukBlSzgQXFg66y6q5qp1nQTD1Cw6NkKBe9WuBlY3iYfmsf7WT8nhlT1CttU
xNCwyMX9mtdXdQicOfNjIGUCD5OLV5PgHFPRKiHHioBAhg==
-----END CERTIFICATE-----
)";
  const std::vector<uint8_t> kName2 = {
      0x30, 0x32, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x0a,
      0x13, 0x11, 0x42, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x53, 0x53, 0x4c,
      0x20, 0x54, 0x45, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x31, 0x14, 0x30,
      0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0b, 0x65, 0x78, 0x61,
      0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d};

  const struct {
    std::vector<std::vector<uint8_t>> existing;
    std::string pem;
    std::vector<std::vector<uint8_t>> expected;
  } kTests[] = {
      // Do nothing.
      {{}, "", {}},
      // Append to an empty list, skipping duplicates.
      {{}, kCert1 + kCert2 + kCert1, {kName1, kName2}},
      // One of the names was already present.
      {{kName1}, kCert1 + kCert2, {kName1, kName2}},
      // Both names were already present.
      {{kName1, kName2}, kCert1 + kCert2, {kName1, kName2}},
      // Preserve existing duplicates.
      {{kName1, kName2, kName2}, kCert1 + kCert2, {kName1, kName2, kName2}},
  };
  for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(kTests); i++) {
    SCOPED_TRACE(i);
    const auto &t = kTests[i];

    bssl::UniquePtr<STACK_OF(X509_NAME)> stack(sk_X509_NAME_new_null());
    ASSERT_TRUE(stack);
    for (const auto &name : t.existing) {
      const uint8_t *inp = name.data();
      bssl::UniquePtr<X509_NAME> name_obj(
          d2i_X509_NAME(nullptr, &inp, name.size()));
      ASSERT_TRUE(name_obj);
      EXPECT_EQ(inp, name.data() + name.size());
      ASSERT_TRUE(bssl::PushToStack(stack.get(), std::move(name_obj)));
    }

    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(t.pem.data(), t.pem.size()));
    ASSERT_TRUE(bio);
    ASSERT_TRUE(SSL_add_bio_cert_subjects_to_stack(stack.get(), bio.get()));

    // The function should have left |stack|'s comparison function alone.
    EXPECT_EQ(nullptr, sk_X509_NAME_set_cmp_func(stack.get(), nullptr));

    std::vector<std::vector<uint8_t>> expected = t.expected, result;
    for (X509_NAME *name : stack.get()) {
      uint8_t *der = nullptr;
      int der_len = i2d_X509_NAME(name, &der);
      ASSERT_GE(der_len, 0);
      result.push_back(std::vector<uint8_t>(der, der + der_len));
      OPENSSL_free(der);
    }

    // |SSL_add_bio_cert_subjects_to_stack| does not return the output in a
    // well-defined order.
    std::sort(expected.begin(), expected.end());
    std::sort(result.begin(), result.end());
    EXPECT_EQ(result, expected);
  }
}

TEST(SSLTest, EmptyClientCAList) {
  if (SkipTempFileTests()) {
    GTEST_SKIP();
  }

  TemporaryFile empty;
  ASSERT_TRUE(empty.Init());
  bssl::UniquePtr<STACK_OF(X509_NAME)> names(
      SSL_load_client_CA_file(empty.path().c_str()));
  EXPECT_FALSE(names);
}

TEST(SSLTest, EmptyWriteBlockedOnHandshakeData) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
      CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  // Configure only TLS 1.3. This test requires post-handshake NewSessionTicket.
  ASSERT_TRUE(SSL_CTX_set_min_proto_version(client_ctx.get(), TLS1_3_VERSION));
  ASSERT_TRUE(SSL_CTX_set_max_proto_version(client_ctx.get(), TLS1_3_VERSION));

  // Connect a client and server with tiny buffer between the two.
  bssl::UniquePtr<SSL> client(SSL_new(client_ctx.get())),
      server(SSL_new(server_ctx.get()));
  ASSERT_TRUE(client);
  ASSERT_TRUE(server);
  SSL_set_connect_state(client.get());
  SSL_set_accept_state(server.get());
  BIO *bio1, *bio2;
  ASSERT_TRUE(BIO_new_bio_pair(&bio1, 1, &bio2, 1));
  SSL_set_bio(client.get(), bio1, bio1);
  SSL_set_bio(server.get(), bio2, bio2);
  ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));

  // We defer NewSessionTicket to the first write, so the server has a pending
  // NewSessionTicket. See https://boringssl-review.googlesource.com/34948. This
  // means an empty write will flush the ticket. However, the transport only
  // allows one byte through, so this will fail with |SSL_ERROR_WANT_WRITE|.
  int ret = SSL_write(server.get(), nullptr, 0);
  ASSERT_EQ(ret, -1);
  ASSERT_EQ(SSL_get_error(server.get(), ret), SSL_ERROR_WANT_WRITE);

  // Attempting to write non-zero data should not trip |SSL_R_BAD_WRITE_RETRY|.
  const uint8_t kData[] = {'h', 'e', 'l', 'l', 'o'};
  ret = SSL_write(server.get(), kData, sizeof(kData));
  ASSERT_EQ(ret, -1);
  ASSERT_EQ(SSL_get_error(server.get(), ret), SSL_ERROR_WANT_WRITE);

  // Byte by byte, the data should eventually get through.
  uint8_t buf[sizeof(kData)];
  for (;;) {
    ret = SSL_read(client.get(), buf, sizeof(buf));
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(SSL_get_error(client.get(), ret), SSL_ERROR_WANT_READ);

    ret = SSL_write(server.get(), kData, sizeof(kData));
    if (ret > 0) {
      ASSERT_EQ(ret, 5);
      break;
    }
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(SSL_get_error(server.get(), ret), SSL_ERROR_WANT_WRITE);
  }

  ret = SSL_read(client.get(), buf, sizeof(buf));
  ASSERT_EQ(ret, static_cast<int>(sizeof(kData)));
  ASSERT_EQ(Bytes(buf, ret), Bytes(kData));
}

// Test that |SSL_ERROR_SYSCALL| continues to work after a close_notify.
TEST(SSLTest, ErrorSyscallAfterCloseNotify) {
  // Make a custom |BIO| where writes fail, but without pushing to the error
  // queue.
  bssl::UniquePtr<BIO_METHOD> method(BIO_meth_new(0, nullptr));
  ASSERT_TRUE(method);
  BIO_meth_set_create(method.get(), [](BIO *b) -> int {
    BIO_set_init(b, 1);
    return 1;
  });
  static bool write_failed = false;
  BIO_meth_set_write(method.get(), [](BIO *, const char *, int) -> int {
    // Fail the operation and don't add to the error queue.
    write_failed = true;
    return -1;
  });
  bssl::UniquePtr<BIO> wbio_silent_error(BIO_new(method.get()));
  ASSERT_TRUE(wbio_silent_error);

  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
      CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));

  // Replace the write |BIO| with |wbio_silent_error|.
  SSL_set0_wbio(client.get(), wbio_silent_error.release());

  // Writes should fail. There is nothing in the error queue, so
  // |SSL_ERROR_SYSCALL| indicates the caller needs to check out-of-band.
  const uint8_t data[1] = {0};
  int ret = SSL_write(client.get(), data, sizeof(data));
  EXPECT_EQ(ret, -1);
  EXPECT_EQ(SSL_get_error(client.get(), ret), SSL_ERROR_SYSCALL);
  EXPECT_TRUE(write_failed);
  write_failed = false;

  // Send a close_notify from the server. It should return 0 because
  // close_notify was sent, but not received. Confusingly, this is a success
  // output for |SSL_shutdown|'s API.
  EXPECT_EQ(SSL_shutdown(server.get()), 0);

  // Read the close_notify on the client.
  uint8_t buf[1];
  ret = SSL_read(client.get(), buf, sizeof(buf));
  EXPECT_EQ(ret, 0);
  EXPECT_EQ(SSL_get_error(client.get(), ret), SSL_ERROR_ZERO_RETURN);

  // Further calls to |SSL_read| continue to report |SSL_ERROR_ZERO_RETURN|.
  ret = SSL_read(client.get(), buf, sizeof(buf));
  EXPECT_EQ(ret, 0);
  EXPECT_EQ(SSL_get_error(client.get(), ret), SSL_ERROR_ZERO_RETURN);

  // Although the client has seen close_notify, it should continue to report
  // |SSL_ERROR_SYSCALL| when its writes fail.
  ret = SSL_write(client.get(), data, sizeof(data));
  EXPECT_EQ(ret, -1);
  EXPECT_EQ(SSL_get_error(client.get(), ret), SSL_ERROR_SYSCALL);
  EXPECT_TRUE(write_failed);
  write_failed = false;

  // Cause |BIO_write| to fail with a return value of zero instead.
  // |SSL_get_error| should not misinterpret this as a close_notify.
  //
  // This is not actually a correct implementation of |BIO_write|, but the rest
  // of the code treats zero from |BIO_write| as an error, so ensure it does so
  // correctly. Fixing https://crbug.com/boringssl/503 will make this case moot.
  BIO_meth_set_write(method.get(), [](BIO *, const char *, int) -> int {
    write_failed = true;
    return 0;
  });
  ret = SSL_write(client.get(), data, sizeof(data));
  EXPECT_EQ(ret, 0);
  EXPECT_EQ(SSL_get_error(client.get(), ret), SSL_ERROR_SYSCALL);
  EXPECT_TRUE(write_failed);
  write_failed = false;
}

// Test that failures are supressed on (potentially)
// transient empty reads.
TEST(SSLTest, IntermittentEmptyRead) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
      CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));

  // Create a fake read BIO that returns 0 on read to simulate empty read
  bssl::UniquePtr<BIO_METHOD> method(BIO_meth_new(0, nullptr));
  ASSERT_TRUE(method);
  ASSERT_TRUE(BIO_meth_set_create(method.get(), [](BIO *b) -> int {
    BIO_set_init(b, 1);
    return 1;
  }));
  ASSERT_TRUE(BIO_meth_set_read(method.get(), [](BIO *, char *, int) -> int {
    return 0;
  }));
  bssl::UniquePtr<BIO> rbio_empty(BIO_new(method.get()));
  ASSERT_TRUE(rbio_empty);
  BIO_set_flags(rbio_empty.get(), BIO_FLAGS_READ);

  // Save off client rbio and use empty read BIO
  bssl::UniquePtr<BIO> client_rbio(SSL_get_rbio(client.get()));
  ASSERT_TRUE(client_rbio);
  // Up-ref |client_rbio| as SSL_CTX dtor will also attempt to free it
  ASSERT_TRUE(BIO_up_ref(client_rbio.get()));
  SSL_set0_rbio(client.get(), rbio_empty.release());

  // Server writes some data to the client
  const uint8_t write_data[] = {1, 2, 3};
  int ret = SSL_write(server.get(), write_data, (int) sizeof(write_data));
  EXPECT_EQ(ret, (int) sizeof(write_data));
  EXPECT_EQ(SSL_get_error(server.get(), ret), SSL_ERROR_NONE);

  uint8_t read_data[] = {0, 0, 0};
  ret = SSL_read(client.get(), read_data, sizeof(read_data));
  EXPECT_EQ(ret, 0);
  // On empty read, client should still want a read so caller will retry.
  // This would have returned |SSL_ERROR_SYSCALL| in OpenSSL 1.0.2.
  EXPECT_EQ(SSL_get_error(client.get(), ret), SSL_ERROR_WANT_READ);

  // Reset client rbio, read should succeed
  SSL_set0_rbio(client.get(), client_rbio.release());
  ret = SSL_read(client.get(), read_data, sizeof(read_data));
  EXPECT_EQ(ret, (int) sizeof(write_data));
  EXPECT_EQ(OPENSSL_memcmp(read_data, write_data, sizeof(write_data)), 0);
  EXPECT_EQ(SSL_get_error(client.get(), ret), SSL_ERROR_NONE);

  // Subsequent attempts to read should fail
  ret = SSL_read(client.get(), read_data, sizeof(read_data));
  EXPECT_LT(ret, 0);
  EXPECT_EQ(SSL_get_error(client.get(), ret), SSL_ERROR_WANT_READ);
}

// Test that |SSL_shutdown|, when quiet shutdown is enabled, simulates receiving
// a close_notify, down to |SSL_read| reporting |SSL_ERROR_ZERO_RETURN|.
TEST(SSLTest, QuietShutdown) {
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL_CTX> server_ctx =
      CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(server_ctx);
  SSL_CTX_set_quiet_shutdown(server_ctx.get(), 1);
  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                     server_ctx.get()));

  // Quiet shutdown is enabled, so |SSL_shutdown| on the server should
  // immediately return that bidirectional shutdown "completed".
  EXPECT_EQ(SSL_shutdown(server.get()), 1);

  // Shut down writes so the client gets an EOF.
  EXPECT_TRUE(BIO_shutdown_wr(SSL_get_wbio(server.get())));

  // Confirm no close notify was actually sent. Client reads should report a
  // transport EOF, not a close_notify. (Both have zero return, but
  // |SSL_get_error| is different.)
  char buf[1];
  int ret = SSL_read(client.get(), buf, sizeof(buf));
  EXPECT_EQ(ret, 0);
  EXPECT_EQ(SSL_get_error(client.get(), ret), SSL_ERROR_SYSCALL);

  // The server believes bidirectional shutdown completed, so reads should
  // replay the (simulated) close_notify.
  ret = SSL_read(server.get(), buf, sizeof(buf));
  EXPECT_EQ(ret, 0);
  EXPECT_EQ(SSL_get_error(server.get(), ret), SSL_ERROR_ZERO_RETURN);
}

TEST(SSLTest, InvalidSignatureAlgorithm) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);

  static const uint16_t kInvalidPrefs[] = {1234};
  EXPECT_FALSE(SSL_CTX_set_signing_algorithm_prefs(
      ctx.get(), kInvalidPrefs, OPENSSL_ARRAY_SIZE(kInvalidPrefs)));
  EXPECT_FALSE(SSL_CTX_set_verify_algorithm_prefs(
      ctx.get(), kInvalidPrefs, OPENSSL_ARRAY_SIZE(kInvalidPrefs)));

  static const uint16_t kDuplicatePrefs[] = {SSL_SIGN_RSA_PKCS1_SHA256,
                                             SSL_SIGN_RSA_PKCS1_SHA256};
  EXPECT_FALSE(SSL_CTX_set_signing_algorithm_prefs(
      ctx.get(), kDuplicatePrefs, OPENSSL_ARRAY_SIZE(kDuplicatePrefs)));
  EXPECT_FALSE(SSL_CTX_set_verify_algorithm_prefs(
      ctx.get(), kDuplicatePrefs, OPENSSL_ARRAY_SIZE(kDuplicatePrefs)));
}

TEST(SSLTest, ErrorStrings) {
  int warning_value = SSL3_AD_CLOSE_NOTIFY | (SSL3_AL_WARNING << 8);
  int fatal_value = SSL3_AD_UNEXPECTED_MESSAGE | (SSL3_AL_FATAL << 8);
  int unknown_value = 99999;

  EXPECT_EQ(Bytes(SSL_alert_desc_string(warning_value)), Bytes("CN"));
  EXPECT_EQ(Bytes(SSL_alert_desc_string(fatal_value)), Bytes("UM"));
  EXPECT_EQ(Bytes(SSL_alert_desc_string(unknown_value)), Bytes("UK"));

  EXPECT_EQ(Bytes(SSL_alert_type_string(warning_value)), Bytes("W"));
  EXPECT_EQ(Bytes(SSL_alert_type_string(fatal_value)), Bytes("F"));
  EXPECT_EQ(Bytes(SSL_alert_type_string(unknown_value)), Bytes("U"));
}

TEST(SSLTest, NameLists) {
  struct {
    size_t (*func)(const char **, size_t);
    std::vector<std::string> expected;
  } kTests[] = {
      {SSL_get_all_version_names, {"TLSv1.3", "DTLSv1.2", "unknown"}},
      {SSL_get_all_standard_cipher_names,
       {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"}},
      {SSL_get_all_cipher_names,
       {"ECDHE-ECDSA-AES128-GCM-SHA256", "TLS_AES_128_GCM_SHA256", "(NONE)"}},
      {SSL_get_all_group_names, {"P-256", "X25519"}},
      {SSL_get_all_signature_algorithm_names,
       {"rsa_pkcs1_sha256", "ecdsa_secp256r1_sha256", "ecdsa_sha256"}},
  };
  for (const auto &t : kTests) {
    size_t num = t.func(nullptr, 0);
    EXPECT_GT(num, 0u);

    std::vector<const char*> list(num);
    EXPECT_EQ(num, t.func(list.data(), list.size()));

    // Check the expected values are in the list.
    for (const auto &s : t.expected) {
      EXPECT_NE(list.end(), std::find(list.begin(), list.end(), s))
          << "Could not find " << s;
    }

    // Passing in a larger buffer should leave excess space alone.
    std::vector<const char *> list2(num + 1, "placeholder");
    EXPECT_EQ(num, t.func(list2.data(), list2.size()));
    for (size_t i = 0; i < num; i++) {
      EXPECT_STREQ(list[i], list2[i]);
    }
    EXPECT_STREQ(list2.back(), "placeholder");

    // Passing in a shorter buffer should truncate the list.
    for (size_t l = 0; l < num; l++) {
      SCOPED_TRACE(l);
      list2.resize(l);
      EXPECT_EQ(num, t.func(list2.data(), list2.size()));
      for (size_t i = 0; i < l; i++) {
        EXPECT_STREQ(list[i], list2[i]);
      }
    }
  }
}

class KemKeyShareTest : public testing::TestWithParam<GroupTest> {};

INSTANTIATE_TEST_SUITE_P(KemKeyShareTests, KemKeyShareTest, testing::ValuesIn(kKemGroupTests));

// Test a successful round-trip for KemKeyShare
TEST_P(KemKeyShareTest, KemKeyShares) {
  GroupTest t = GetParam();
  bssl::UniquePtr<SSLKeyShare> client_key_share = bssl::SSLKeyShare::Create(t.group_id);
  bssl::UniquePtr<SSLKeyShare> server_key_share = bssl::SSLKeyShare::Create(t.group_id);
  ASSERT_TRUE(client_key_share);
  ASSERT_TRUE(server_key_share);
  EXPECT_EQ(t.group_id, client_key_share->GroupID());
  EXPECT_EQ(t.group_id, server_key_share->GroupID());

  // The client generates its key pair and outputs the public key.
  // We initialize the CBB with a capacity of 2 as a sanity check to
  // ensure that the CBB will grow accordingly if necessary.
  CBB client_out_public_key;
  EXPECT_TRUE(CBB_init(&client_out_public_key, 2));
  EXPECT_TRUE(client_key_share->Offer(&client_out_public_key));
  EXPECT_EQ(CBB_len(&client_out_public_key), t.offer_key_share_size);

  // The server accepts the public key, generates the shared secret,
  // and outputs the ciphertext. Again, we initialize the CBB with
  // a capacity of 2 to ensure it will grow accordingly.
  CBB server_out_public_key;
  EXPECT_TRUE(CBB_init(&server_out_public_key, 2));
  uint8_t server_alert = 0;
  Array<uint8_t> server_secret;
  const uint8_t *client_out_public_key_data = CBB_data(&client_out_public_key);
  ASSERT_TRUE(client_out_public_key_data);
  Span<const uint8_t> client_public_key =
    MakeConstSpan(client_out_public_key_data, CBB_len(&client_out_public_key));
  EXPECT_TRUE(server_key_share->Accept(&server_out_public_key, &server_secret,
                                       &server_alert, client_public_key));
  EXPECT_EQ(CBB_len(&server_out_public_key), t.accept_key_share_size);
  EXPECT_EQ(server_secret.size(), t.shared_secret_size);
  EXPECT_EQ(server_alert, 0);

  // The client accepts the ciphertext and decrypts it to obtain
  // the shared secret.
  uint8_t client_alert = 0;
  Array<uint8_t> client_secret;
  const uint8_t *server_out_public_key_data = CBB_data(&server_out_public_key);
  ASSERT_TRUE(server_out_public_key_data);
  Span<const uint8_t> server_public_key =
    MakeConstSpan(server_out_public_key_data, CBB_len(&server_out_public_key));
  EXPECT_TRUE(client_key_share->Finish(&client_secret, &client_alert, server_public_key));
  EXPECT_EQ(client_secret.size(), t.shared_secret_size);
  EXPECT_EQ(client_alert, 0);

  // Verify that client and server arrived at the same shared secret.
  EXPECT_EQ(Bytes(client_secret), Bytes(server_secret));

  CBB_cleanup(&client_out_public_key);
  CBB_cleanup(&server_out_public_key);
}

class BadKemKeyShareOfferTest : public testing::TestWithParam<GroupTest> {};
INSTANTIATE_TEST_SUITE_P(BadKemKeyShareOfferTests, BadKemKeyShareOfferTest, testing::ValuesIn(kKemGroupTests));

// Test failure cases for KEMKeyShare::Offer()
TEST_P(BadKemKeyShareOfferTest, BadKemKeyShareOffers) {
  GroupTest t = GetParam();
  // Basic nullptr checks
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(client_key_share);

    ASSERT_FALSE(client_key_share->Offer(nullptr));
  }

  // Offer() should fail if |client_out_public_key| has children
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(client_key_share);
    CBB client_out_public_key;
    CBB child;

    EXPECT_TRUE(CBB_init(&client_out_public_key, 2));
    client_out_public_key.child = &child;
    EXPECT_FALSE(client_key_share->Offer(&client_out_public_key));
    CBB_cleanup(&client_out_public_key);
  }

  // Offer() should succeed on the first call, but fail on all repeated calls
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(client_key_share);
    CBB client_out_public_key;

    EXPECT_TRUE(CBB_init(&client_out_public_key, 2));
    EXPECT_TRUE(client_key_share->Offer(&client_out_public_key));
    EXPECT_FALSE(client_key_share->Offer(&client_out_public_key));
    EXPECT_FALSE(client_key_share->Offer(&client_out_public_key));
    CBB_cleanup(&client_out_public_key);
  }

  // Offer() should fail if Accept() was previously called
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = bssl::SSLKeyShare::Create(t.group_id);
    bssl::UniquePtr<SSLKeyShare> server_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(client_key_share);
    ASSERT_TRUE(server_key_share);
    uint8_t server_alert = 0;
    Array<uint8_t> server_secret;
    CBB client_out_public_key;
    CBB server_out_public_key;
    CBB server_offer_out;

    EXPECT_TRUE(CBB_init(&client_out_public_key, t.offer_key_share_size));
    EXPECT_TRUE(CBB_init(&server_out_public_key, t.accept_key_share_size));
    EXPECT_TRUE(CBB_init(&server_offer_out, t.offer_key_share_size));

    EXPECT_TRUE(client_key_share->Offer(&client_out_public_key));
    const uint8_t *client_public_key_data = CBB_data(&client_out_public_key);
    Span<const uint8_t> client_public_key =
      MakeConstSpan(client_public_key_data, CBB_len(&client_out_public_key));

    EXPECT_TRUE(server_key_share->Accept(&server_out_public_key, &server_secret, &server_alert, client_public_key));
    EXPECT_EQ(server_alert, 0);

    EXPECT_FALSE(server_key_share->Offer(&server_offer_out));

    CBB_cleanup(&client_out_public_key);
    CBB_cleanup(&server_out_public_key);
    CBB_cleanup(&server_offer_out);
  }

  // |client_out_public_key| is properly initialized, some zeros are written
  // to it so that it records a non-zero length, then its buffer is
  // invalidated.
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(client_key_share);
    CBB client_out_public_key;
    CBB_init(&client_out_public_key, t.offer_key_share_size);
    EXPECT_TRUE(CBB_add_zeros(&client_out_public_key, 2));
    // Keep a pointer to the buffer so we can cleanup correctly
    uint8_t *buf = client_out_public_key.u.base.buf;
    client_out_public_key.u.base.buf = nullptr;
    EXPECT_EQ(CBB_len(&client_out_public_key), (size_t) 2);
    EXPECT_FALSE(client_key_share->Offer(&client_out_public_key));
    client_out_public_key.u.base.buf = buf;
    CBB_cleanup(&client_out_public_key);
  }
}

TEST(SSLTest, SessionPrint) {
 static const std::array<std::string, 15> kExpectedTLS13{
      {"SSL-Session:", "    Protocol  :", "    Cipher    : ",
       "    Session-ID: ", "    Session-ID-ctx:", "    Resumption PSK:",
       "    PSK identity:", "    TLS session ticket lifetime hint:",
       "    TLS session ticket:", "    61",
       "    Start Time:", "    Timeout   :", "    Verify return code:",
       "    Extended master secret:", "    Max Early Data:"}};

  static const std::array<std::string, 14> kExpectedTLS12{
      {"SSL-Session:", "    Protocol  :", "    Cipher    : ",
       "    Session-ID: ", "    Session-ID-ctx:", "    Master-Key:",
       "    PSK identity:", "    TLS session ticket lifetime hint:",
       "    TLS session ticket:", "    61",
       "    Start Time:", "    Timeout   :", "    Verify return code:",
       "    Extended master secret:"}};

  bssl::UniquePtr<SSL_SESSION> session(
      CreateSessionWithTicket(TLS1_3_VERSION, 10));
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  EXPECT_TRUE(SSL_SESSION_print(bio.get(), session.get()));
  const uint8_t *out;
  size_t outlen;
  ASSERT_TRUE(BIO_mem_contents(bio.get(), &out, &outlen));

  // Iterate through |kExpectedTLS13| and verify that |SSL_SESSION_print| has
  // the expected format.
  std::istringstream iss_tls13((std::string((char *)out, outlen)));
  std::string line;
  for (const auto &expected : kExpectedTLS13) {
    std::getline(iss_tls13, line);
    EXPECT_EQ(line.substr(0, expected.length()), expected);
  }

  session = CreateSessionWithTicket(TLS1_2_VERSION, 10);
  bio.reset(BIO_new(BIO_s_mem()));
  EXPECT_TRUE(SSL_SESSION_print(bio.get(), session.get()));
  ASSERT_TRUE(BIO_mem_contents(bio.get(), &out, &outlen));
  // Iterate through |kExpectedTLS12| and verify that |SSL_SESSION_print| has
  // the expected format.
  std::istringstream iss_tls12((std::string((char *)out, outlen)));
  for (const auto &expected : kExpectedTLS12) {
    std::getline(iss_tls12, line);
    EXPECT_EQ(line.substr(0, expected.length()), expected);
  }
}

class BadKemKeyShareAcceptTest : public testing::TestWithParam<GroupTest> {};
INSTANTIATE_TEST_SUITE_P(BadKemKeyShareAcceptTests, BadKemKeyShareAcceptTest, testing::ValuesIn(kKemGroupTests));

// Test failure cases for KEMKeyShare::Accept()
TEST_P(BadKemKeyShareAcceptTest, BadKemKeyShareAccept) {
  GroupTest t = GetParam();
  // Basic nullptr checks
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    uint8_t server_alert = 0;
    Array<uint8_t> server_secret;
    Span<const uint8_t> client_public_key;
    CBB server_out_public_key;

    EXPECT_FALSE(server_key_share->Accept(nullptr, &server_secret,
                                          &server_alert, client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_INTERNAL_ERROR);
    server_alert = 0;

    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key, nullptr,
                                          &server_alert, client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_INTERNAL_ERROR);
    server_alert = 0;

    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key,
                                          &server_secret, nullptr,
                                          client_public_key));
  }

  // |server_out_public_key| is properly initialized, then is assigned a child
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    uint8_t server_alert = 0;
    Array<uint8_t> server_secret;
    Span<const uint8_t> client_public_key;
    CBB server_out_public_key;
    CBB child;

    CBB_init(&server_out_public_key, t.accept_key_share_size);
    server_out_public_key.child = &child;
    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key,
                                          &server_secret, &server_alert,
                                          client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_INTERNAL_ERROR);
    CBB_cleanup(&server_out_public_key);
  }

  // |server_out_public_key| is properly initialized with CBB_init,
  // some zeros are written to it so that it records a non-zero length,
  // then its buffer is invalidated.
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    uint8_t server_alert = 0;
    Array<uint8_t> server_secret;
    Span<const uint8_t> client_public_key;
    CBB server_out_public_key;

    CBB_init(&server_out_public_key, t.accept_key_share_size);
    EXPECT_TRUE(CBB_add_zeros(&server_out_public_key, 2));
    // Keep a pointer to the buffer so we can cleanup correctly
    uint8_t *buf = server_out_public_key.u.base.buf;
    server_out_public_key.u.base.buf = nullptr;
    EXPECT_EQ(CBB_len(&server_out_public_key), (size_t) 2);
    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key,
                                          &server_secret, &server_alert,
                                          client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_INTERNAL_ERROR);
    server_out_public_key.u.base.buf = buf;
    CBB_cleanup(&server_out_public_key);
  }

  // KemKeyShare::Accept() should fail if KemKeyShare::Offer() has been
  // previously called by that peer. The server should have no reason to
  // call Offer(); enforcing this case will guard against that type of bug.
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    uint8_t server_alert = 0;
    Array<uint8_t> server_secret;
    CBB server_out_public_key;
    CBB server_offer_out;

    EXPECT_TRUE(CBB_init(&server_out_public_key, t.accept_key_share_size));
    EXPECT_TRUE(CBB_init(&server_offer_out, t.offer_key_share_size));
    EXPECT_TRUE(server_key_share->Offer(&server_offer_out));
    const uint8_t *server_offer_out_data = CBB_data(&server_offer_out);
    ASSERT_TRUE(server_offer_out_data);
    Span<const uint8_t> server_offered_pk =
      MakeConstSpan(server_offer_out_data, CBB_len(&server_offer_out));
    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key,
                                          &server_secret, &server_alert,
                                          server_offered_pk));
    EXPECT_EQ(server_alert, SSL_AD_INTERNAL_ERROR);
    CBB_cleanup(&server_out_public_key);
    CBB_cleanup(&server_offer_out);
  }

  // |client_public_key| is initialized with too little data
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = bssl::SSLKeyShare::Create(t.group_id);
    bssl::UniquePtr<SSLKeyShare> client_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    ASSERT_TRUE(client_key_share);
    Span<const uint8_t> client_public_key;
    Array<uint8_t> server_secret;
    CBB server_out_public_key;
    CBB client_out_public_key;
    uint8_t server_alert = 0;

    // Generate a valid |client_public_key|, then truncate the last byte
    EXPECT_TRUE(CBB_init(&client_out_public_key, 64));
    EXPECT_TRUE(client_key_share->Offer(&client_out_public_key));
    const uint8_t *client_out_public_key_data = CBB_data(&client_out_public_key);
    ASSERT_TRUE(client_out_public_key_data);
    client_public_key = MakeConstSpan(client_out_public_key_data,
                                      CBB_len(&client_out_public_key) - 1);

    EXPECT_TRUE(CBB_init(&server_out_public_key, t.accept_key_share_size));
    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key,
                                          &server_secret, &server_alert,
                                          client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_ILLEGAL_PARAMETER);
    CBB_cleanup(&server_out_public_key);
    CBB_cleanup(&client_out_public_key);
  }

  // |client_public_key| is initialized with too much data
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = bssl::SSLKeyShare::Create(t.group_id);
    bssl::UniquePtr<SSLKeyShare> client_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    ASSERT_TRUE(client_key_share);
    Span<const uint8_t> client_public_key;
    Array<uint8_t> server_secret;
    CBB server_out_public_key;
    CBB client_out_public_key;
    uint8_t server_alert = 0;

    // Generate a valid |client_public_key|, then append a byte
    EXPECT_TRUE(CBB_init(&client_out_public_key, 64));
    EXPECT_TRUE(client_key_share->Offer(&client_out_public_key));
    EXPECT_TRUE(CBB_add_zeros(&client_out_public_key, 1));
    const uint8_t *client_out_public_key_data = CBB_data(&client_out_public_key);
    ASSERT_TRUE(client_out_public_key_data);
    client_public_key = MakeConstSpan(client_out_public_key_data,
                                      CBB_len(&client_out_public_key));

    EXPECT_TRUE(CBB_init(&server_out_public_key, t.accept_key_share_size));
    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key,
                                          &server_secret, &server_alert,
                                          client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_ILLEGAL_PARAMETER);
    CBB_cleanup(&server_out_public_key);
    CBB_cleanup(&client_out_public_key);
  }

  // |client_public_key| has been initialized but is empty
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    uint8_t server_alert = 0;
    Array<uint8_t> server_secret;
    CBB server_out_public_key;

    EXPECT_TRUE(CBB_init(&server_out_public_key, t.accept_key_share_size));
    const uint8_t empty_client_public_key_buf[] = {0};
    Span<const uint8_t> client_public_key =
      MakeConstSpan(empty_client_public_key_buf, 0);
    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key,
                                          &server_secret, &server_alert,
                                          client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_DECODE_ERROR);
    CBB_cleanup(&server_out_public_key);
  }

  // |client_public_key| is initialized with key material that is the correct
  // length, but it doesn't match the corresponding secret key. The exchange
  // will succeed, but the client and the server will end up with different
  // secrets, and the overall handshake will eventually fail.
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = bssl::SSLKeyShare::Create(t.group_id);
    bssl::UniquePtr<SSLKeyShare> client_key_share = bssl::SSLKeyShare::Create(t.group_id);
    bssl::UniquePtr<SSLKeyShare> random_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    ASSERT_TRUE(client_key_share);
    ASSERT_TRUE(random_key_share);
    uint8_t server_alert = 0;
    uint8_t client_alert = 0;
    Array<uint8_t> server_secret;
    Array<uint8_t> client_secret;
    CBB server_out_public_key;
    CBB client_out_public_key;
    CBB random_out_public_key;

    // Start by having the client Offer() its public key
    EXPECT_TRUE(CBB_init(&client_out_public_key, t.offer_key_share_size));
    EXPECT_TRUE(client_key_share->Offer(&client_out_public_key));

    // Generate a random public key that is incompatible with client's secret key
    EXPECT_TRUE(CBB_init(&random_out_public_key, t.offer_key_share_size));
    EXPECT_TRUE(random_key_share->Offer(&random_out_public_key));
    const uint8_t *random_out_public_key_data = CBB_data(&random_out_public_key);
    ASSERT_TRUE(random_out_public_key_data);
    Span<const uint8_t> client_public_key =
      MakeConstSpan(random_out_public_key_data, t.offer_key_share_size);

    // When the server calls Accept() with the modified public key, it will
    // return success
    EXPECT_TRUE(CBB_init(&server_out_public_key, t.accept_key_share_size));
    EXPECT_TRUE(server_key_share->Accept(&server_out_public_key,
                                         &server_secret, &server_alert,
                                         client_public_key));

    // And when the client calls Finish(), it will also return success
    const uint8_t *server_out_public_key_data = CBB_data(&server_out_public_key);
    ASSERT_TRUE(server_out_public_key_data);
    Span<const uint8_t> server_public_key =
      MakeConstSpan(server_out_public_key_data, CBB_len(&server_out_public_key));
    EXPECT_TRUE(client_key_share->Finish(&client_secret, &client_alert,
                                         server_public_key));

    // The shared secrets are of the correct length...
    EXPECT_EQ(client_secret.size(), t.shared_secret_size);
    EXPECT_EQ(server_secret.size(), t.shared_secret_size);

    // ... but they are not equal
    EXPECT_NE(Bytes(client_secret), Bytes(server_secret));

    EXPECT_EQ(server_alert, 0);
    EXPECT_EQ(client_alert, 0);
    CBB_cleanup(&server_out_public_key);
    CBB_cleanup(&client_out_public_key);
    CBB_cleanup(&random_out_public_key);
  }
}

class BadKemKeyShareFinishTest : public testing::TestWithParam<GroupTest> {};
INSTANTIATE_TEST_SUITE_P(BadKemKeyShareFinishTests, BadKemKeyShareFinishTest, testing::ValuesIn(kKemGroupTests));

TEST_P(BadKemKeyShareFinishTest, BadKemKeyShareFinish) {
  GroupTest t = GetParam();

  // Basic nullptr checks
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(client_key_share);
    Span<const uint8_t> server_public_key;
    Array<uint8_t> client_secret;
    uint8_t client_alert = 0;

    EXPECT_FALSE(client_key_share->Finish(nullptr, &client_alert,
                                         server_public_key));
    EXPECT_EQ(client_alert, SSL_AD_INTERNAL_ERROR);
    client_alert = 0;

    EXPECT_FALSE(client_key_share->Finish(&client_secret, nullptr,
                                         server_public_key));
  }

  // A call to Finish() should fail if Offer() was not called previously
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(client_key_share);
    Span<const uint8_t> server_public_key;
    Array<uint8_t> client_secret;
    uint8_t client_alert = 0;

    EXPECT_FALSE(client_key_share->Finish(&client_secret, &client_alert,
                                         server_public_key));
    EXPECT_EQ(client_alert, SSL_AD_INTERNAL_ERROR);
  }

  // Set up the client and server states for the remaining tests
  bssl::UniquePtr<SSLKeyShare> server_key_share = bssl::SSLKeyShare::Create(t.group_id);
  bssl::UniquePtr<SSLKeyShare> client_key_share = bssl::SSLKeyShare::Create(t.group_id);
  bssl::UniquePtr<SSLKeyShare> random_key_share = bssl::SSLKeyShare::Create(t.group_id);
  ASSERT_TRUE(server_key_share);
  ASSERT_TRUE(client_key_share);
  ASSERT_TRUE(random_key_share);
  CBB client_out_public_key;
  CBB server_out_public_key;
  CBB random_out_public_key;
  Array<uint8_t> server_secret;
  Array<uint8_t> client_secret;
  uint8_t client_alert = 0;
  uint8_t server_alert = 0;
  Span<const uint8_t> client_public_key;
  Span<const uint8_t> server_public_key;

  EXPECT_TRUE(CBB_init(&client_out_public_key, t.offer_key_share_size));
  EXPECT_TRUE(CBB_init(&server_out_public_key, t.accept_key_share_size));
  EXPECT_TRUE(CBB_init(&random_out_public_key, t.accept_key_share_size));
  EXPECT_TRUE(client_key_share->Offer(&client_out_public_key));
  const uint8_t *client_out_public_key_data = CBB_data(&client_out_public_key);
  ASSERT_TRUE(client_out_public_key_data);
  client_public_key = MakeConstSpan(client_out_public_key_data,
                                    CBB_len(&client_out_public_key));
  EXPECT_TRUE(server_key_share->Accept(&server_out_public_key, &server_secret,
                                      &server_alert, client_public_key));
  EXPECT_EQ(server_alert, 0);

  // |server_public_key| has been initialized with too little data. Here, we
  // initialize |server_public_key| with a fragment of an otherwise valid
  // key. However, it doesn't matter if it is a fragment of a valid key, or
  // complete garbage, the client will reject it all the same.
  {
    const uint8_t *server_out_public_key_data = CBB_data(&server_out_public_key);
    ASSERT_TRUE(server_out_public_key_data);
    server_public_key = MakeConstSpan(server_out_public_key_data, t.accept_key_share_size - 1);
    EXPECT_FALSE(client_key_share->Finish(&client_secret, &client_alert, server_public_key));
    EXPECT_EQ(client_alert, SSL_AD_INTERNAL_ERROR);
    client_alert = 0;
  }

  // |server_public_key| has been initialized with too much data. Here, we
  // initialize |server_public_key| with a valid public key, and over-read
  // the buffer to append a random byte. However, it doesn't matter if it is a
  // valid key with nonsense appended, or complete garbage, the client will
  // reject it all the same.
  {
    const uint8_t *server_out_public_key_data = CBB_data(&server_out_public_key);
    ASSERT_TRUE(server_out_public_key_data);
    server_public_key = MakeConstSpan(server_out_public_key_data, t.accept_key_share_size + 1);
    EXPECT_FALSE(client_key_share->Finish(&client_secret, &client_alert, server_public_key));
    EXPECT_EQ(client_alert, SSL_AD_INTERNAL_ERROR);
    client_alert = 0;
  }

  // |server_public_key| is initialized with a modified key of the correct
  // length. The decapsulation operations will succeed; however, the resulting
  // shared secret will be garbage, and eventually the overall handshake
  // would fail because the client secret does not match the server secret.
  {
    // The server's public key was already correctly generated previously in
    // a call to Accept(). Here we modify it by replacing it with a randomly
    // generated public key that is incompatible with the secret key
    EXPECT_TRUE(random_key_share->Offer(&random_out_public_key));
    const uint8_t *random_out_public_key_data = CBB_data(&random_out_public_key);
    ASSERT_TRUE(random_out_public_key_data);
    server_public_key =
     MakeConstSpan(random_out_public_key_data, t.accept_key_share_size);

    // The call to Finish() will return success
    EXPECT_TRUE(client_key_share->Finish(&client_secret, &client_alert, server_public_key));
    EXPECT_EQ(client_alert, 0);

    // The shared secrets are of the correct length...
    EXPECT_EQ(client_secret.size(), t.shared_secret_size);
    EXPECT_EQ(server_secret.size(), t.shared_secret_size);

    // ... but they are not equal
    EXPECT_NE(Bytes(client_secret), Bytes(server_secret));
  }

  CBB_cleanup(&server_out_public_key);
  CBB_cleanup(&client_out_public_key);
  CBB_cleanup(&random_out_public_key);
}

class HybridKeyShareTest : public testing::TestWithParam<HybridGroupTest> {};
INSTANTIATE_TEST_SUITE_P(HybridKeyShareTests, HybridKeyShareTest, testing::ValuesIn(kHybridGroupTests));

// Test a successful round-trip for HybridKeyShare
TEST_P(HybridKeyShareTest, HybridKeyShares) {
  HybridGroupTest t = GetParam();

  // Set up client and server with test case parameters
  bssl::UniquePtr<SSLKeyShare> client_key_share = SSLKeyShare::Create(t.group_id);
  bssl::UniquePtr<SSLKeyShare> server_key_share = SSLKeyShare::Create(t.group_id);
  ASSERT_TRUE(client_key_share);
  ASSERT_TRUE(server_key_share);
  EXPECT_EQ(t.group_id, client_key_share->GroupID());
  EXPECT_EQ(t.group_id, server_key_share->GroupID());

  // The client generates its key pair and outputs the public key.
  // We initialize the CBB with a capacity of 2 as a simple sanity check
  // to ensure that the CBB will grow accordingly when necessary.
  CBB client_out_public_key;
  EXPECT_TRUE(CBB_init(&client_out_public_key, 2));
  EXPECT_TRUE(client_key_share->Offer(&client_out_public_key));
  EXPECT_EQ(CBB_len(&client_out_public_key), t.offer_key_share_size);

  // The server accepts the public key, generates the shared secret,
  // and outputs the ciphertext. Again, we initialize the CBB with
  // a capacity of 2 to ensure it will grow accordingly.
  CBB server_out_public_key;
  EXPECT_TRUE(CBB_init(&server_out_public_key, 2));
  uint8_t server_alert = 0;
  Array<uint8_t> server_secret;
  const uint8_t *client_out_public_key_data = CBB_data(&client_out_public_key);
  ASSERT_TRUE(client_out_public_key_data);
  Span<const uint8_t> client_public_key =
    MakeConstSpan(client_out_public_key_data, CBB_len(&client_out_public_key));
  EXPECT_TRUE(server_key_share->Accept(&server_out_public_key, &server_secret,
                                       &server_alert, client_public_key));
  EXPECT_EQ(CBB_len(&server_out_public_key), t.accept_key_share_size);
  EXPECT_EQ(server_alert, 0);

  // The client accepts the server's public key and decrypts it to obtain
  // the shared secret.
  uint8_t client_alert = 0;
  Array<uint8_t> client_secret;
  const uint8_t *server_out_public_key_data = CBB_data(&server_out_public_key);
  ASSERT_TRUE(server_out_public_key_data);
  Span<const uint8_t> server_public_key = MakeConstSpan(
    server_out_public_key_data, CBB_len(&server_out_public_key));
  EXPECT_TRUE(client_key_share->Finish(&client_secret, &client_alert, server_public_key));
  EXPECT_EQ(client_alert, 0);

  // Verify that client and server arrived at the same shared secret.
  EXPECT_EQ(server_secret.size(), t.shared_secret_size);
  EXPECT_EQ(client_secret.size(), t.shared_secret_size);
  EXPECT_EQ(Bytes(client_secret), Bytes(server_secret));

  CBB_cleanup(&client_out_public_key);
  CBB_cleanup(&server_out_public_key);

}

class BadHybridKeyShareOfferTest : public testing::TestWithParam<HybridGroupTest> {};
INSTANTIATE_TEST_SUITE_P(BadHybridKeyShareOfferTests, BadHybridKeyShareOfferTest, testing::ValuesIn(kHybridGroupTests));

// Test failure cases for HybridKeyShare::Offer()
TEST_P(BadHybridKeyShareOfferTest, BadHybridKeyShareOffers) {
  HybridGroupTest t = GetParam();
  // Basic nullptr check
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(client_key_share);

    ASSERT_FALSE(client_key_share->Offer(nullptr));
  }

  // Offer() should fail if |client_out| has not been initialized at all.
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(client_key_share);
    CBB client_out_public_key;
    CBB_zero(&client_out_public_key);

    EXPECT_FALSE(client_key_share->Offer(&client_out_public_key));
  }

  // Offer() should fail if the CBB has children
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(client_key_share);
    CBB client_out_public_key;
    EXPECT_TRUE(CBB_init(&client_out_public_key, 64));
    CBB child;

    client_out_public_key.child = &child;
    EXPECT_FALSE(client_key_share->Offer(&client_out_public_key));
    CBB_cleanup(&client_out_public_key);
  }

  // Offer() should succeed on the first call, but fail on all repeated calls
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = bssl::SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(client_key_share);
    CBB client_out_public_key;

    EXPECT_TRUE(CBB_init(&client_out_public_key, 2));
    EXPECT_TRUE(client_key_share->Offer(&client_out_public_key));
    EXPECT_FALSE(client_key_share->Offer(&client_out_public_key));
    EXPECT_FALSE(client_key_share->Offer(&client_out_public_key));
    CBB_cleanup(&client_out_public_key);
  }

  // |client_out| is properly initialized, some zeros are written
  // to it so that it records a non-zero length, then its buffer is
  // invalidated.
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(client_key_share);
    CBB client_out_public_key;

    CBB_init(&client_out_public_key, t.offer_key_share_size);
    EXPECT_TRUE(CBB_add_zeros(&client_out_public_key, 2));
    // Keep a pointer to the buffer so we can cleanup correctly
    uint8_t *buf = client_out_public_key.u.base.buf;
    client_out_public_key.u.base.buf = nullptr;
    EXPECT_EQ(CBB_len(&client_out_public_key), (size_t) 2);
    EXPECT_FALSE(client_key_share->Offer(&client_out_public_key));
    client_out_public_key.u.base.buf = buf;
    CBB_cleanup(&client_out_public_key);
  }
}

class BadHybridKeyShareAcceptTest : public testing::TestWithParam<HybridGroupTest> {};
INSTANTIATE_TEST_SUITE_P(BadHybridKeyShareAcceptTests, BadHybridKeyShareAcceptTest, testing::ValuesIn(kHybridGroupTests));

// Test failure cases for HybridKeyShare::Accept()
TEST_P(BadHybridKeyShareAcceptTest, BadHybridKeyShareAccept) {
  HybridGroupTest t = GetParam();
  // Basic nullptr checks
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    Span<const uint8_t> client_public_key;
    Array<uint8_t> server_secret;
    CBB server_out_public_key;
    uint8_t server_alert = 0;

    EXPECT_FALSE(server_key_share->Accept(nullptr, &server_secret,
                                          &server_alert, client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_INTERNAL_ERROR);
    server_alert = 0;

    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key, nullptr,
                                          &server_alert, client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_INTERNAL_ERROR);
    server_alert = 0;

    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key,
                                          &server_secret, nullptr,
                                          client_public_key));
  }

  // |server_out_public_key| has not been initialized
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    Span<const uint8_t> client_public_key;
    Array<uint8_t> server_secret;
    CBB server_out_public_key;
    uint8_t server_alert = 0;

    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key,
                                          &server_secret, &server_alert,
                                          client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_INTERNAL_ERROR);
  }

  // |server_out_public_key| is properly initialized, then is assigned a child
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    Span<const uint8_t> client_public_key;
    Array<uint8_t> server_secret;
    CBB server_out_public_key;
    uint8_t server_alert = 0;
    CBB child;

    CBB_init(&server_out_public_key, 64);
    server_out_public_key.child = &child;
    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key,
                                          &server_secret, &server_alert,
                                          client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_INTERNAL_ERROR);
    CBB_cleanup(&server_out_public_key);
  }

  // |server_out_public_key| is properly initialized with CBB_init,
  // some zeros are written to it so that it records a non-zero length,
  // then its buffer is invalidated.
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    Span<const uint8_t> client_public_key;
    Array<uint8_t> server_secret;
    CBB server_out_public_key;
    uint8_t server_alert = 0;

    CBB_init(&server_out_public_key, t.accept_key_share_size);
    EXPECT_TRUE(CBB_add_zeros(&server_out_public_key, 2));
    // Keep a pointer to the buffer so we can cleanup correctly
    uint8_t *buf = server_out_public_key.u.base.buf;
    server_out_public_key.u.base.buf = nullptr;
    EXPECT_EQ(CBB_len(&server_out_public_key), (size_t) 2);
    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key,
                                          &server_secret, &server_alert,
                                          client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_INTERNAL_ERROR);
    server_out_public_key.u.base.buf = buf;
    CBB_cleanup(&server_out_public_key);
  }

  // |client_public_key| has not been initialized with anything
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    Span<const uint8_t> client_public_key;
    Array<uint8_t> server_secret;
    CBB server_out_public_key;
    uint8_t server_alert = 0;

    EXPECT_TRUE(CBB_init(&server_out_public_key, 64));
    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key,
                                          &server_secret, &server_alert,
                                          client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_INTERNAL_ERROR);
    CBB_cleanup(&server_out_public_key);
  }

  // |client_public_key| has been initialized but is empty
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    Array<uint8_t> server_secret;
    CBB server_out_public_key;
    uint8_t server_alert = 0;

    const uint8_t empty_buffer[1] = {0}; // Arrays must have at least 1 element to compile on Windows
    Span<const uint8_t> client_public_key = MakeConstSpan(empty_buffer, 0);

    EXPECT_TRUE(CBB_init(&server_out_public_key, 64));
    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key,
                                          &server_secret, &server_alert,
                                          client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_ILLEGAL_PARAMETER);
    CBB_cleanup(&server_out_public_key);
  }

  // |client_public_key| is initialized with too little data
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = SSLKeyShare::Create(t.group_id);
    bssl::UniquePtr<SSLKeyShare> client_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    ASSERT_TRUE(client_key_share);
    Span<const uint8_t> client_public_key;
    Array<uint8_t> server_secret;
    CBB server_out_public_key;
    CBB client_out_public_key;
    uint8_t server_alert = 0;

    // Generate a valid |client_public_key|, then truncate the last byte
    EXPECT_TRUE(CBB_init(&client_out_public_key, 64));
    EXPECT_TRUE(client_key_share->Offer(&client_out_public_key));
    const uint8_t *client_out_public_key_data = CBB_data(&client_out_public_key);
    ASSERT_TRUE(client_out_public_key_data);
    client_public_key = MakeConstSpan(client_out_public_key_data,
                                      CBB_len(&client_out_public_key) - 1);

    EXPECT_TRUE(CBB_init(&server_out_public_key, 64));
    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key,
                                          &server_secret, &server_alert,
                                          client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_ILLEGAL_PARAMETER);
    CBB_cleanup(&server_out_public_key);
    CBB_cleanup(&client_out_public_key);
  }

  // |client_public_key| is initialized with too much data
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = SSLKeyShare::Create(t.group_id);
    bssl::UniquePtr<SSLKeyShare> client_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    ASSERT_TRUE(client_key_share);
    Span<const uint8_t> client_public_key;
    Array<uint8_t> server_secret;
    CBB server_out_public_key;
    CBB client_out_public_key;
    uint8_t server_alert = 0;

    // Generate a valid |client_public_key|, then append a byte
    EXPECT_TRUE(CBB_init(&client_out_public_key, 64));
    EXPECT_TRUE(client_key_share->Offer(&client_out_public_key));
    EXPECT_TRUE(CBB_add_zeros(&client_out_public_key, 1));
    const uint8_t *client_out_public_key_data = CBB_data(&client_out_public_key);
    ASSERT_TRUE(client_out_public_key_data);
    client_public_key = MakeConstSpan(client_out_public_key_data,
                                      CBB_len(&client_out_public_key));

    EXPECT_TRUE(CBB_init(&server_out_public_key, 64));
    EXPECT_FALSE(server_key_share->Accept(&server_out_public_key,
                                          &server_secret, &server_alert,
                                          client_public_key));
    EXPECT_EQ(server_alert, SSL_AD_DECODE_ERROR);
    CBB_cleanup(&server_out_public_key);
    CBB_cleanup(&client_out_public_key);
  }

  // |client_public_key| is initialized with key material that is the correct
  // length, but is not a valid key. We do this iteratively over each
  // component group that makes up the hybrid group so that we can test
  // all Accept() code paths in the hybrid key share.
  {
    size_t client_public_key_index = 0;
    for (size_t i = 0; i < NUM_HYBRID_COMPONENTS; i++) {
      // We'll need the hybrid group to retrieve the component share sizes
      const HybridGroup *hybrid_group = GetHybridGroup(t.group_id);
      ASSERT_TRUE(hybrid_group != NULL);

      // Create the hybrid key shares and generate a valid |client_public_key|
      bssl::UniquePtr<SSLKeyShare> client_key_share = SSLKeyShare::Create(t.group_id);
      bssl::UniquePtr<SSLKeyShare> server_key_share = SSLKeyShare::Create(t.group_id);
      ASSERT_TRUE(client_key_share);
      ASSERT_TRUE(server_key_share);

      CBB client_out_public_key;
      CBB server_out_public_key;
      EXPECT_TRUE(CBB_init(&client_out_public_key, 64));
      EXPECT_TRUE(CBB_init(&server_out_public_key, 64));

      Array<uint8_t> server_secret;
      Array<uint8_t> client_secret;
      uint8_t client_alert = 0;
      uint8_t server_alert = 0;

      EXPECT_TRUE(client_key_share->Offer(&client_out_public_key));

      // For the current component group, overwrite the bytes of that
      // component's key share (and *only* that component's key share) with
      // arbitrary nonsense; leave all other sections of the key share alone.
      // This ensures:
      // 1. The overall size of the hybrid key share is still correct
      // 2. The sizes of the component key shares are still correct; in other
      //    words, the component key shares are still partitioned correctly
      //    and will be parsed individually, as intended
      // 2. The key share associated with the current component group is invalid
      // 3. All other component key shares are still valid
      //
      // (We have to do this in a roundabout way with malloc'ing another
      // buffer because CBBs cannot be arbitrarily edited.)
      size_t client_out_public_key_len = CBB_len(&client_out_public_key);
      const uint8_t *client_out_public_key_data = CBB_data(&client_out_public_key);
      ASSERT_TRUE(client_out_public_key_data);
      uint8_t *buffer = (uint8_t *)OPENSSL_malloc(client_out_public_key_len);
      ASSERT_TRUE(buffer);
      OPENSSL_memcpy(buffer, client_out_public_key_data, client_out_public_key_len);

      for (size_t j = client_public_key_index; j < client_public_key_index + t.offer_share_sizes[i]; j++) {
        buffer[j] = 7; // 7 is arbitrary
      }
      Span<const uint8_t> client_public_key =
        MakeConstSpan(buffer, client_out_public_key_len);

      // The server will Accept() the invalid public key
      bool accepted = server_key_share->
        Accept(&server_out_public_key, &server_secret, &server_alert, client_public_key);

      if (accepted) {
        // The Accept() functionality for X25519 and all KEM key shares is
        // written so that, even if the given public key is invalid, it will
        // return success, output its own public key, and continue with the
        // handshake. (This is the intended functionality.) So, in this
        // case, we assert that the component group was one of those groups,
        // continue with the handshake, then verify that the client and
        // server ultimately arrived at different shared secrets.
        EXPECT_TRUE(
          hybrid_group->component_group_ids[i] == SSL_GROUP_KYBER768_R3 ||
          hybrid_group->component_group_ids[i] == SSL_GROUP_MLKEM768 ||
          hybrid_group->component_group_ids[i] == SSL_GROUP_MLKEM1024 ||
          hybrid_group->component_group_ids[i] == SSL_GROUP_X25519
        );

        // The handshake will complete without error...
        EXPECT_EQ(server_alert, 0);
        EXPECT_EQ(server_secret.size(), t.shared_secret_size);

        Span<const uint8_t> server_public_key = MakeConstSpan(
          CBB_data(&server_out_public_key), CBB_len(&server_out_public_key));
        EXPECT_TRUE(client_key_share->Finish(&client_secret, &client_alert, server_public_key));
        EXPECT_EQ(client_secret.size(), t.shared_secret_size);
        EXPECT_EQ(client_alert, 0);

        // ...but client and server will arrive at different shared secrets
        EXPECT_NE(Bytes(client_secret), Bytes(server_secret));

      } else {
        // The Accept() functionality for the NIST curves (e.g. P256) is
        // written so that it will return failure if the key share is invalid.
        EXPECT_TRUE(
          hybrid_group->component_group_ids[i] == SSL_GROUP_SECP256R1 ||
          hybrid_group->component_group_ids[i] == SSL_GROUP_SECP384R1
        );
        EXPECT_EQ(server_alert, SSL_AD_ILLEGAL_PARAMETER);
      }

      client_public_key_index += t.offer_share_sizes[i];
      CBB_cleanup(&client_out_public_key);
      CBB_cleanup(&server_out_public_key);
      OPENSSL_free(buffer);
    }
  }
}


class BadHybridKeyShareFinishTest : public testing::TestWithParam<HybridGroupTest> {};
INSTANTIATE_TEST_SUITE_P(BadHybridKeyShareFinishTests, BadHybridKeyShareFinishTest, testing::ValuesIn(kHybridGroupTests));

// Test failure cases for HybridKeyShare::Finish()
TEST_P(BadHybridKeyShareFinishTest, BadHybridKeyShareFinish) {
  HybridGroupTest t = GetParam();
  // Basic nullptr checks
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = SSLKeyShare::Create(t.group_id);
    Span<const uint8_t> server_public_key;
    Array<uint8_t> client_secret;
    uint8_t client_alert = 0;
    CBB client_public_key_out;
    CBB_init(&client_public_key_out, 2);
    EXPECT_TRUE(client_key_share->Offer(&client_public_key_out));

    EXPECT_FALSE(client_key_share->Finish(nullptr, &client_alert, server_public_key));
    EXPECT_EQ(client_alert, SSL_AD_INTERNAL_ERROR);
    client_alert = 0;

    EXPECT_FALSE(client_key_share->Finish(&client_secret, nullptr, server_public_key));

    CBB_cleanup(&client_public_key_out);
  }

  // It is an error if Finish() is called without there
  // having been a previous call to Offer()
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(client_key_share);
    Array<uint8_t> client_secret;
    uint8_t client_alert = 0;
    uint8_t *buffer = (uint8_t *)OPENSSL_malloc(t.accept_key_share_size);

    Span<const uint8_t> server_public_key = MakeConstSpan(buffer, t.accept_key_share_size);

    EXPECT_FALSE(client_key_share->Finish(&client_secret, &client_alert, server_public_key));
    EXPECT_EQ(client_alert, SSL_AD_INTERNAL_ERROR);

    OPENSSL_free(buffer);
  }

  // |server_public_key| has not been initialized with anything
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = SSLKeyShare::Create(t.group_id);
    Span<const uint8_t> server_public_key;
    Array<uint8_t> client_secret;
    uint8_t client_alert = 0;
    CBB client_public_key_out;
    CBB_init(&client_public_key_out, 2);

    EXPECT_TRUE(client_key_share->Offer(&client_public_key_out));

    EXPECT_FALSE(client_key_share->Finish(&client_secret, &client_alert, server_public_key));
    EXPECT_EQ(client_alert, SSL_AD_INTERNAL_ERROR);

    CBB_cleanup(&client_public_key_out);
  }

  // |server_public_key| is initialized but is empty
  {
    bssl::UniquePtr<SSLKeyShare> client_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(client_key_share);
    Array<uint8_t> client_secret;
    uint8_t client_alert = 0;
    const uint8_t empty_buffer[1] = {0}; // Arrays must have at least 1 element to compile on Windows
    Span<const uint8_t> server_public_key = MakeConstSpan(empty_buffer, 0);
    CBB client_public_key_out;
    CBB_init(&client_public_key_out, 2);

    EXPECT_TRUE(client_key_share->Offer(&client_public_key_out));

    EXPECT_FALSE(client_key_share->Finish(&client_secret, &client_alert, server_public_key));
    CBB_cleanup(&client_public_key_out);
    EXPECT_EQ(client_alert, SSL_AD_DECODE_ERROR);
  }

  // |server_public_key| is initialized with too little data
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = SSLKeyShare::Create(t.group_id);
    bssl::UniquePtr<SSLKeyShare> client_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    ASSERT_TRUE(client_key_share);
    Span<const uint8_t> client_public_key;
    Span<const uint8_t> server_public_key;
    Array<uint8_t> server_secret;
    Array<uint8_t> client_secret;
    CBB server_out_public_key;
    CBB client_out_public_key;
    uint8_t server_alert = 0;
    uint8_t client_alert = 0;

    // Generate a valid |client_public_key|
    EXPECT_TRUE(CBB_init(&client_out_public_key, 64));
    EXPECT_TRUE(client_key_share->Offer(&client_out_public_key));
    const uint8_t *client_out_public_key_data = CBB_data(&client_out_public_key);
    ASSERT_TRUE(client_out_public_key_data);
    client_public_key = MakeConstSpan(client_out_public_key_data,
                                      CBB_len(&client_out_public_key));

    // Generate a valid |server_public_key|, then truncate the last byte
    EXPECT_TRUE(CBB_init(&server_out_public_key, 64));
    EXPECT_TRUE(server_key_share->Accept(&server_out_public_key,
                                         &server_secret, &server_alert,
                                         client_public_key));
    EXPECT_EQ(server_alert, 0);
    const uint8_t *server_out_public_key_data = CBB_data(&server_out_public_key);
    ASSERT_TRUE(server_out_public_key_data);
    server_public_key = MakeConstSpan(server_out_public_key_data,
                                      CBB_len(&server_out_public_key) - 1);

    EXPECT_FALSE(client_key_share->Finish(&client_secret, &client_alert, server_public_key));
    EXPECT_EQ(client_alert, SSL_AD_DECODE_ERROR);

    CBB_cleanup(&server_out_public_key);
    CBB_cleanup(&client_out_public_key);
  }

  // |server_public_key| is initialized with too much data
  {
    bssl::UniquePtr<SSLKeyShare> server_key_share = SSLKeyShare::Create(t.group_id);
    bssl::UniquePtr<SSLKeyShare> client_key_share = SSLKeyShare::Create(t.group_id);
    ASSERT_TRUE(server_key_share);
    ASSERT_TRUE(client_key_share);
    Span<const uint8_t> client_public_key;
    Span<const uint8_t> server_public_key;
    Array<uint8_t> server_secret;
    Array<uint8_t> client_secret;
    CBB server_out_public_key;
    CBB client_out_public_key;
    uint8_t server_alert = 0;
    uint8_t client_alert = 0;

    // Generate a valid |client_public_key|
    EXPECT_TRUE(CBB_init(&client_out_public_key, 64));
    EXPECT_TRUE(client_key_share->Offer(&client_out_public_key));
    const uint8_t *client_out_public_key_data = CBB_data(&client_out_public_key);
    ASSERT_TRUE(client_out_public_key_data);
    client_public_key = MakeConstSpan(client_out_public_key_data,
                                      CBB_len(&client_out_public_key));

    // Generate a valid |server_public_key|, then append a byte
    EXPECT_TRUE(CBB_init(&server_out_public_key, 64));
    EXPECT_TRUE(server_key_share->Accept(&server_out_public_key,
                                         &server_secret, &server_alert,
                                         client_public_key));
    EXPECT_EQ(server_alert, 0);
    EXPECT_TRUE(CBB_add_zeros(&server_out_public_key, 1));
    const uint8_t *server_out_public_key_data = CBB_data(&server_out_public_key);
    ASSERT_TRUE(server_out_public_key_data);
    server_public_key = MakeConstSpan(server_out_public_key_data,
                                      CBB_len(&server_out_public_key));

    EXPECT_FALSE(client_key_share->Finish(&client_secret, &client_alert, server_public_key));
    EXPECT_EQ(client_alert, SSL_AD_ILLEGAL_PARAMETER);

    CBB_cleanup(&server_out_public_key);
    CBB_cleanup(&client_out_public_key);
  }

  // |server_public_key| is initialized with key material that is the correct
  // length, but is not a valid key. We do this iteratively over each
  // component group that makes up the hybrid group so that we can test
  // all Finish() code paths in the hybrid key share.
  {
    size_t server_public_key_index = 0;
    for (size_t i = 0; i < NUM_HYBRID_COMPONENTS; i++) {
      // We'll need the hybrid group to retrieve the component share sizes
      const HybridGroup *hybrid_group = GetHybridGroup(t.group_id);
      ASSERT_TRUE(hybrid_group != NULL);

      // Create the hybrid key shares and generate a valid |server_public_key|
      bssl::UniquePtr<SSLKeyShare> client_key_share = SSLKeyShare::Create(t.group_id);
      bssl::UniquePtr<SSLKeyShare> server_key_share = SSLKeyShare::Create(t.group_id);
      ASSERT_TRUE(client_key_share);
      ASSERT_TRUE(server_key_share);

      CBB client_out_public_key;
      CBB server_out_public_key;
      EXPECT_TRUE(CBB_init(&client_out_public_key, 64));
      EXPECT_TRUE(CBB_init(&server_out_public_key, 64));

      Array<uint8_t> server_secret;
      Array<uint8_t> client_secret;
      uint8_t client_alert = 0;
      uint8_t server_alert = 0;

      EXPECT_TRUE(client_key_share->Offer(&client_out_public_key));

      Span<const uint8_t> client_public_key = MakeConstSpan(
        CBB_data(&client_out_public_key), CBB_len(&client_out_public_key));
      EXPECT_TRUE(server_key_share->Accept(&server_out_public_key,
                                           &server_secret, &server_alert,
                                           client_public_key));
      EXPECT_EQ(server_alert, 0);

      // For the current component group, overwrite the bytes of that
      // component's key share (and *only* that component's key share) with
      // arbitrary nonsense; leave all other sections of the key share alone.
      // This ensures:
      // 1. The overall size of the hybrid key share is still correct
      // 2. The sizes of the component key shares are still correct; in other
      //    words, the component key shares are still partitioned correctly
      //    and will be parsed individually, as intended
      // 2. The key share associated with the current component group is invalid
      // 3. All other component key shares are still valid
      //
      // (We have to do this in a roundabout way with malloc'ing another
      // buffer because CBBs cannot be arbitrarily edited.)
      size_t server_out_public_key_len = CBB_len(&server_out_public_key);
      const uint8_t *server_out_public_key_data = CBB_data(&server_out_public_key);
      ASSERT_TRUE(server_out_public_key_data);
      uint8_t *buffer = (uint8_t *)OPENSSL_malloc(server_out_public_key_len);
      ASSERT_TRUE(buffer);
      OPENSSL_memcpy(buffer, server_out_public_key_data, server_out_public_key_len);
      for (size_t j = server_public_key_index; j < server_public_key_index + t.accept_share_sizes[i]; j++) {
        buffer[j] = 7; // 7 is arbitrary
      }
      Span<const uint8_t> server_public_key =
        MakeConstSpan(buffer, server_out_public_key_len);

      // The client will Finish() with the invalid public key
      bool accepted = client_key_share->Finish(&client_secret, &client_alert,
                                               server_public_key);

      if (accepted) {
        // The Finish() functionality for X25519 and all KEM key shares is
        // written so that, even if the given public key is invalid, it will
        // return success, output its own public key, and continue with the
        // handshake. (This is the intended functionality.) So, in this
        // case, we assert that the component group was one of those groups,
        // continue with the handshake, then verify that the client and
        // server ultimately arrived at different shared secrets.
        EXPECT_TRUE(
          hybrid_group->component_group_ids[i] == SSL_GROUP_KYBER768_R3 ||
          hybrid_group->component_group_ids[i] == SSL_GROUP_MLKEM768 ||
          hybrid_group->component_group_ids[i] == SSL_GROUP_MLKEM1024 ||
          hybrid_group->component_group_ids[i] == SSL_GROUP_X25519
        );

        // The handshake will complete without error...
        EXPECT_EQ(client_alert, 0);
        EXPECT_EQ(client_secret.size(), t.shared_secret_size);

        // ...but client and server will arrive at different shared secrets
        EXPECT_NE(Bytes(client_secret), Bytes(server_secret));

      } else {
        // The Finish() functionality for the NIST curves (e.g. P256) is
        // written so that it will return failure if the key share is invalid.
        EXPECT_TRUE(
          hybrid_group->component_group_ids[i] == SSL_GROUP_SECP256R1 ||
          hybrid_group->component_group_ids[i] == SSL_GROUP_SECP384R1
        );
        EXPECT_EQ(client_alert, SSL_AD_ILLEGAL_PARAMETER);
      }

      server_public_key_index += t.accept_share_sizes[i];
      CBB_cleanup(&client_out_public_key);
      CBB_cleanup(&server_out_public_key);
      OPENSSL_free(buffer);
    }
  }
}

class PerformHybridHandshakeTest : public testing::TestWithParam<HybridHandshakeTest> {};
INSTANTIATE_TEST_SUITE_P(PerformHybridHandshakeTests, PerformHybridHandshakeTest, testing::ValuesIn(kHybridHandshakeTests));

// This test runs through an overall handshake flow for all of the cases
// defined in kHybridHandshakeTests. This test runs through both positive and
// negative cases; refer to the comments inline in kHybridHandshakeTests for
// specifics about each test case.
TEST_P(PerformHybridHandshakeTest, PerformHybridHandshake) {
  HybridHandshakeTest t = GetParam();
  // Set up client and server with test case parameters
  bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(client_ctx);
  ASSERT_TRUE(SSL_CTX_set1_curves_list(client_ctx.get(), t.client_rule));
  ASSERT_TRUE(
      SSL_CTX_set_max_proto_version(client_ctx.get(), t.client_version));

  bssl::UniquePtr<SSL_CTX> server_ctx =
      CreateContextWithTestCertificate(TLS_method());
  ASSERT_TRUE(server_ctx);
  ASSERT_TRUE(SSL_CTX_set1_curves_list(server_ctx.get(), t.server_rule));
  ASSERT_TRUE(
      SSL_CTX_set_max_proto_version(server_ctx.get(), t.server_version));

  bssl::UniquePtr<SSL> client, server;
  ASSERT_TRUE(CreateClientAndServer(&client, &server, client_ctx.get(),
                                    server_ctx.get()));

  if (t.expected_group != 0) {
    // In this case, assert that the handshake completes as expected.
    ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));

    SSL_SESSION *client_session = SSL_get_session(client.get());
    ASSERT_TRUE(client_session);
    EXPECT_EQ(t.expected_group, client_session->group_id);
    EXPECT_EQ(t.is_hrr_expected, SSL_used_hello_retry_request(client.get()));
    EXPECT_EQ(std::min(t.client_version, t.server_version),
              client_session->ssl_version);

    SSL_SESSION *server_session = SSL_get_session(server.get());
    ASSERT_TRUE(server_session);
    EXPECT_EQ(t.expected_group, server_session->group_id);
    EXPECT_EQ(t.is_hrr_expected, SSL_used_hello_retry_request(server.get()));
    EXPECT_EQ(std::min(t.client_version, t.server_version),
              server_session->ssl_version);
  } else {
    // In this case, we expect the handshake to fail because client and
    // server configurations are not compatible.
    ASSERT_FALSE(CompleteHandshakes(client.get(), server.get()));

    ASSERT_FALSE(client.get()->s3->initial_handshake_complete);
    EXPECT_EQ(t.is_hrr_expected, SSL_used_hello_retry_request(client.get()));

    ASSERT_FALSE(server.get()->s3->initial_handshake_complete);
    EXPECT_EQ(t.is_hrr_expected, SSL_used_hello_retry_request(server.get()));
  }
}

TEST(SSLTest, SSLFileTests) {
#if defined(OPENSSL_ANDROID)
  // On Android, when running from an APK, temporary file creations do not work.
  // See b/36991167#comment8.
  GTEST_SKIP();
#endif

  char rsa_pem_filename[PATH_MAX];
  char ecdsa_pem_filename[PATH_MAX];
  ASSERT_TRUE(createTempFILEpath(rsa_pem_filename));
  ASSERT_TRUE(createTempFILEpath(ecdsa_pem_filename));

  ScopedFILE rsa_pem(fopen(rsa_pem_filename, "w"));
  ScopedFILE ecdsa_pem(fopen(ecdsa_pem_filename, "w"));
  ASSERT_TRUE(rsa_pem);
  ASSERT_TRUE(ecdsa_pem);

  bssl::UniquePtr<X509> rsa_leaf = GetChainTestCertificate();
  bssl::UniquePtr<X509> rsa_intermediate = GetChainTestIntermediate();
  bssl::UniquePtr<X509> ecdsa_leaf = GetECDSATestCertificate();
  ASSERT_TRUE(PEM_write_X509(rsa_pem.get(), rsa_leaf.get()));
  ASSERT_TRUE(PEM_write_X509(rsa_pem.get(), rsa_intermediate.get()));
  ASSERT_TRUE(PEM_write_X509(ecdsa_pem.get(), ecdsa_leaf.get()));
  rsa_pem.reset();
  ecdsa_pem.reset();

  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  // Load a certificate into |ctx| and verify that |ssl| inherits it.
  EXPECT_TRUE(SSL_CTX_use_certificate_chain_file(ctx.get(), rsa_pem_filename));
  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl);
  EXPECT_EQ(X509_cmp(SSL_get_certificate(ssl.get()), rsa_leaf.get()), 0);

  // Load a new cert into |ssl| and verify that it's correctly loaded.
  EXPECT_TRUE(SSL_use_certificate_chain_file(ssl.get(), ecdsa_pem_filename));
  EXPECT_EQ(X509_cmp(SSL_get_certificate(ssl.get()), ecdsa_leaf.get()), 0);

  ASSERT_EQ(remove(rsa_pem_filename), 0);
  ASSERT_EQ(remove(ecdsa_pem_filename), 0);
}

TEST(SSLTest, IncompatibleTLSVersionState) {
  // Using the following ASN.1 DER Sequence where 42 is the serialization
  // format version number of some future version not currently supported:
  // SEQUENCE {
  //   SEQUENCE {
  //     INTEGER { 42 }
  //   }
  // }
  static constexpr size_t INCOMPATIBLE_DER_LEN = 7;
  static const uint8_t INCOMPATIBLE_DER[INCOMPATIBLE_DER_LEN] = {
      0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x2a};

  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);

  ASSERT_FALSE(
      SSL_from_bytes(INCOMPATIBLE_DER, INCOMPATIBLE_DER_LEN, ctx.get()));
  ASSERT_EQ(ERR_GET_LIB(ERR_peek_error()), ERR_LIB_SSL);
  ASSERT_EQ(ERR_GET_REASON(ERR_peek_error()),
            SSL_R_SERIALIZATION_INVALID_SERDE_VERSION);
}

// Test that it is possible for the certificate to be configured on a mix of
// SSL_CTX and SSL. This ensures that we do not inadvertently overshare objects
// in SSL_new.
TEST(SSLTest, MixContextAndConnection) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  ASSERT_TRUE(ctx);
  bssl::UniquePtr<X509> cert = GetTestCertificate();
  ASSERT_TRUE(cert);
  bssl::UniquePtr<EVP_PKEY> key = GetTestKey();
  ASSERT_TRUE(key);

  // Configure the certificate, but not the private key, on the context.
  ASSERT_TRUE(SSL_CTX_use_certificate(ctx.get(), cert.get()));

  bssl::UniquePtr<SSL> ssl1(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl1.get());
  bssl::UniquePtr<SSL> ssl2(SSL_new(ctx.get()));
  ASSERT_TRUE(ssl2.get());

  // There is no private key configured yet.
  EXPECT_FALSE(SSL_CTX_get0_privatekey(ctx.get()));
  EXPECT_FALSE(SSL_get_privatekey(ssl1.get()));
  EXPECT_FALSE(SSL_get_privatekey(ssl2.get()));

  // Configuring the private key on |ssl1| works.
  ASSERT_TRUE(SSL_use_PrivateKey(ssl1.get(), key.get()));
  EXPECT_TRUE(SSL_get_privatekey(ssl1.get()));

  // It does not impact the other connection or the context.
  EXPECT_FALSE(SSL_CTX_get0_privatekey(ctx.get()));
  EXPECT_FALSE(SSL_get_privatekey(ssl2.get()));
}

static size_t test_ecc_privkey_calls = 0;

static enum ssl_private_key_result_t test_ecc_privkey_complete(SSL *ssl,
                                                           uint8_t *out,
                                                           size_t *out_len,
                                                           size_t max_out) {
  test_ecc_privkey_calls += 1;
  return ssl_private_key_success;
}

static enum ssl_private_key_result_t test_ecc_privkey_sign(
    SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out,
    uint16_t signature_algorithm, const uint8_t *in, size_t in_len) {
  bssl::UniquePtr<EVP_PKEY> pkey(GetECDSATestKey());

  if (EVP_PKEY_id(pkey.get()) !=
      SSL_get_signature_algorithm_key_type(signature_algorithm)) {
      return ssl_private_key_failure;
  }

  const EVP_MD *md = SSL_get_signature_algorithm_digest(signature_algorithm);
  bssl::ScopedEVP_MD_CTX ctx;
  EVP_PKEY_CTX *pctx = nullptr;
  if (!EVP_DigestSignInit(ctx.get(), &pctx, md, nullptr,
                          pkey.get())) {
    return ssl_private_key_failure;
  }

  size_t len = 0;
  if (!EVP_DigestSign(ctx.get(), nullptr, &len, in, in_len) || len > max_out) {
    return ssl_private_key_failure;
  }

  *out_len = max_out;

  if (!EVP_DigestSign(ctx.get(), out, out_len, in, in_len)) {
    return ssl_private_key_failure;
  }

  return test_ecc_privkey_complete(ssl, out, out_len, max_out);
}

static enum ssl_private_key_result_t test_ecc_privkey_decrypt(
    SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in,
    size_t in_len) {
  return ssl_private_key_failure;
}

static const SSL_PRIVATE_KEY_METHOD test_ecc_private_key_method = {
    test_ecc_privkey_sign,
    test_ecc_privkey_decrypt,
    test_ecc_privkey_complete,
};

TEST(SSLTest, SSLPrivateKeyMethod) {
  {
    bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
    bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_method()));

    bssl::UniquePtr<X509> ecdsa_cert(GetECDSATestCertificate());
    bssl::UniquePtr<CRYPTO_BUFFER> ecdsa_leaf =
        x509_to_buffer(ecdsa_cert.get());
    std::vector<CRYPTO_BUFFER *> chain = {
        ecdsa_leaf.get(),
    };

    // Index should be have been set to default, 0, but no key loaded
    EXPECT_EQ(server_ctx->cert->cert_private_key_idx, SSL_PKEY_RSA);
    EXPECT_EQ(
        server_ctx->cert->cert_private_keys[SSL_PKEY_RSA].privatekey.get(),
        nullptr);
    EXPECT_EQ(server_ctx->cert->key_method, nullptr);


    // Load a certificate chain containg the leaf but set private key method
    ASSERT_TRUE(SSL_CTX_set_chain_and_key(server_ctx.get(), &chain[0],
                                          chain.size(), nullptr,
                                          &test_ecc_private_key_method));

    // Should be initiall zero
    ASSERT_EQ(test_ecc_privkey_calls, (size_t)0);

    // Index must be ECC key now, but key_method must be set.
    ASSERT_EQ(server_ctx->cert->cert_private_key_idx, SSL_PKEY_ECC);
    ASSERT_EQ(server_ctx->cert->key_method, &test_ecc_private_key_method);

    bssl::UniquePtr<SSL> client, server;
    ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                       server_ctx.get(), ClientConfig(),
                                       false));

    ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));

    ASSERT_EQ(test_ecc_privkey_calls, (size_t)1);

    // Check the internal slot index to verify that the correct slot was used
    // during the handshake.
    ASSERT_EQ(server->config->cert->cert_private_key_idx, SSL_PKEY_ECC);
    ASSERT_EQ(server->config->cert->key_method, &test_ecc_private_key_method);
  }

  {
    size_t current_invoke_count = test_ecc_privkey_calls;

    bssl::UniquePtr<SSL_CTX> client_ctx(SSL_CTX_new(TLS_method()));
    bssl::UniquePtr<SSL_CTX> server_ctx(SSL_CTX_new(TLS_method()));

    // Index should be have been set to default, 0, but no key loaded
    EXPECT_EQ(server_ctx->cert->cert_private_key_idx, SSL_PKEY_RSA);
    EXPECT_EQ(
        server_ctx->cert->cert_private_keys[SSL_PKEY_RSA].privatekey.get(),
        nullptr);
    EXPECT_EQ(server_ctx->cert->key_method, nullptr);

    bssl::UniquePtr<X509> ed_cert(GetED25519TestCertificate());
    bssl::UniquePtr<EVP_PKEY> ed_key(GetED25519TestKey());
    bssl::UniquePtr<CRYPTO_BUFFER> ed_leaf = x509_to_buffer(ed_cert.get());
    std::vector<CRYPTO_BUFFER *> ed_chain = {
        ed_leaf.get(),
    };

    // Load a certificate chain containg the leaf but set private key method
    ASSERT_TRUE(SSL_CTX_set_chain_and_key(server_ctx.get(), &ed_chain[0],
                                          ed_chain.size(), ed_key.get(),
                                          nullptr));

    // Index must be ECC key now, but key_method must not be set.
    ASSERT_EQ(server_ctx->cert->cert_private_key_idx, SSL_PKEY_ED25519);
    ASSERT_EQ(server_ctx->cert->key_method, nullptr);

    std::vector<uint16_t> sigalgs = {SSL_SIGN_ED25519};

    ASSERT_TRUE(SSL_CTX_set_signing_algorithm_prefs(
        client_ctx.get(), sigalgs.data(), sigalgs.size()));
    ASSERT_TRUE(SSL_CTX_set_verify_algorithm_prefs(
        client_ctx.get(), sigalgs.data(), sigalgs.size()));

    bssl::UniquePtr<SSL> client, server;
    ASSERT_TRUE(ConnectClientAndServer(&client, &server, client_ctx.get(),
                                       server_ctx.get(), ClientConfig(),
                                       false));

    ASSERT_TRUE(CompleteHandshakes(client.get(), server.get()));

    // This should still be the same, as we didn't use the private key method
    // functionality, so it shouldn't have incremented.
    ASSERT_EQ(test_ecc_privkey_calls, current_invoke_count);

    // Check the internal slot index to verify that the correct slot was used
    // during the handshake and that key_method was not set.
    ASSERT_EQ(server->config->cert->cert_private_key_idx, SSL_PKEY_ED25519);
    ASSERT_EQ(server->config->cert->key_method, nullptr);
  }
}

}  // namespace
BSSL_NAMESPACE_END
