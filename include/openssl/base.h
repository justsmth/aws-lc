/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

#ifndef OPENSSL_HEADER_BASE_H
#define OPENSSL_HEADER_BASE_H


// This file should be the first included by all BoringSSL headers.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#if defined(__MINGW32__)
// stdio.h is needed on MinGW for __MINGW_PRINTF_FORMAT.
#include <stdio.h>
#endif

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

// Include an AWS-LC-only header so consumers including this header without
// setting up include paths do not accidentally pick up the system
// opensslconf.h.
#include <openssl/is_awslc.h>
#include <openssl/opensslconf.h>
#include <openssl/target.h>  // IWYU pragma: export

#include <openssl/boringssl_prefix_symbols.h>

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(BORINGSSL_FIPS)
#define AWSLC_FIPS
#endif

#if defined(__APPLE__)
// Note |TARGET_OS_MAC| is set for all Apple OS variants. |TARGET_OS_OSX|
// targets macOS specifically.
#if defined(TARGET_OS_OSX) && TARGET_OS_OSX
#define OPENSSL_MACOS
#endif
#if defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE
#define OPENSSL_IOS
#endif
#endif

#define AWSLC_VERSION_NAME "AWS-LC"
#define OPENSSL_IS_AWSLC
// |OPENSSL_VERSION_NUMBER| should match the version number in opensslv.h.
#define OPENSSL_VERSION_NUMBER 0x1010107f
#define SSLEAY_VERSION_NUMBER OPENSSL_VERSION_NUMBER

// BORINGSSL_API_VERSION is replaced with AWSLC_API_VERSION to avoid users interpreting AWSLC as BoringSSL.
// Below are BoringSSL's comments on BORINGSSL_API_VERSION.
// BORINGSSL_API_VERSION is a positive integer that increments as BoringSSL
// changes over time. The value itself is not meaningful. It will be incremented
// whenever is convenient to coordinate an API change with consumers. This will
// not denote any special point in development.
//
// A consumer may use this symbol in the preprocessor to temporarily build
// against multiple revisions of BoringSSL at the same time. It is not
// recommended to do so for longer than is necessary.
#define AWSLC_API_VERSION 35

// This string tracks the most current production release version on Github
// https://github.com/aws/aws-lc/releases.
// When bumping the encoded version number, also update the test fixture:
// ServiceIndicatorTest.AWSLCVersionString
// Note: there are two versions of this test. Only one test is compiled
// depending on FIPS mode.
#define AWSLC_VERSION_NUMBER_STRING "1.56.0"

#if defined(BORINGSSL_SHARED_LIBRARY)

#if defined(OPENSSL_WINDOWS)

#if defined(BORINGSSL_IMPLEMENTATION)
#define OPENSSL_EXPORT __declspec(dllexport)
#else
#define OPENSSL_EXPORT __declspec(dllimport)
#endif

#else  // defined(OPENSSL_WINDOWS)

#if defined(BORINGSSL_IMPLEMENTATION)
#define OPENSSL_EXPORT __attribute__((visibility("default")))
#else
#define OPENSSL_EXPORT
#endif

#endif  // defined(OPENSSL_WINDOWS)

#else  // defined(BORINGSSL_SHARED_LIBRARY)

#if defined(OPENSSL_WINDOWS)
#define OPENSSL_EXPORT
#else
#define OPENSSL_EXPORT __attribute__((visibility("default")))
#endif

#endif  // defined(BORINGSSL_SHARED_LIBRARY)

#if !defined(OPENSSL_WARN_UNUSED_RESULT)
// This should only affect internal usage of functions
#if defined(BORINGSSL_IMPLEMENTATION) || defined(AWS_LC_TEST_ENV)
#if defined(__GNUC__) || defined(__clang__)
# define OPENSSL_WARN_UNUSED_RESULT __attribute__ ((warn_unused_result))
#elif defined(_MSC_VER)
# define OPENSSL_WARN_UNUSED_RESULT _Check_return_
#else
# define OPENSSL_WARN_UNUSED_RESULT
#endif
#else
// The macro is ignored by consumers
# define OPENSSL_WARN_UNUSED_RESULT
#endif
#endif

#if defined(_MSC_VER)

// OPENSSL_DEPRECATED is used to mark a function as deprecated. Use
// of any functions so marked in caller code will produce a warning.
// OPENSSL_BEGIN_ALLOW_DEPRECATED and OPENSSL_END_ALLOW_DEPRECATED
// can be used to suppress the warning in regions of caller code.
#define OPENSSL_DEPRECATED __declspec(deprecated)
#define OPENSSL_BEGIN_ALLOW_DEPRECATED \
  __pragma(warning(push)) __pragma(warning(disable : 4996))
#define OPENSSL_END_ALLOW_DEPRECATED __pragma(warning(pop))

#elif (defined(__GNUC__) && ((__GNUC__ > 4) ||  (__GNUC_MINOR__ >= 6))) || defined(__clang__)
// `_Pragma("GCC diagnostic push")` was added in GCC 4.6
// http://gcc.gnu.org/gcc-4.6/changes.html
#define OPENSSL_DEPRECATED __attribute__((__deprecated__))
#define OPENSSL_BEGIN_ALLOW_DEPRECATED \
  _Pragma("GCC diagnostic push")       \
      _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#define OPENSSL_END_ALLOW_DEPRECATED _Pragma("GCC diagnostic pop")

#else

#define OPENSSL_DEPRECATED
#define OPENSSL_BEGIN_ALLOW_DEPRECATED
#define OPENSSL_END_ALLOW_DEPRECATED

#endif


#if defined(__GNUC__) || defined(__clang__)
// MinGW has two different printf implementations. Ensure the format macro
// matches the selected implementation. See
// https://sourceforge.net/p/mingw-w64/wiki2/gnu%20printf/.
#if defined(__MINGW_PRINTF_FORMAT)
#define OPENSSL_PRINTF_FORMAT_FUNC(string_index, first_to_check) \
  __attribute__(                                                 \
      (__format__(__MINGW_PRINTF_FORMAT, string_index, first_to_check)))
#else
#define OPENSSL_PRINTF_FORMAT_FUNC(string_index, first_to_check) \
  __attribute__((__format__(__printf__, string_index, first_to_check)))
#endif
#else
#define OPENSSL_PRINTF_FORMAT_FUNC(string_index, first_to_check)
#endif

// OPENSSL_CLANG_PRAGMA emits a pragma on clang and nothing on other compilers.
#if defined(__clang__)
#define OPENSSL_CLANG_PRAGMA(arg) _Pragma(arg)
#else
#define OPENSSL_CLANG_PRAGMA(arg)
#endif

// OPENSSL_MSVC_PRAGMA emits a pragma on MSVC and nothing on other compilers.
#if defined(_MSC_VER)
#define OPENSSL_MSVC_PRAGMA(arg) __pragma(arg)
#else
#define OPENSSL_MSVC_PRAGMA(arg)
#endif

#if defined(__GNUC__) || defined(__clang__)
#define OPENSSL_UNUSED __attribute__((unused))
#else
#define OPENSSL_UNUSED
#endif

// C and C++ handle inline functions differently. In C++, an inline function is
// defined in just the header file, potentially emitted in multiple compilation
// units (in cases the compiler did not inline), but each copy must be identical
// to satsify ODR. In C, a non-static inline must be manually emitted in exactly
// one compilation unit with a separate extern inline declaration.
//
// In both languages, exported inline functions referencing file-local symbols
// are problematic. C forbids this altogether (though GCC and Clang seem not to
// enforce it). It works in C++, but ODR requires the definitions be identical,
// including all names in the definitions resolving to the "same entity". In
// practice, this is unlikely to be a problem, but an inline function that
// returns a pointer to a file-local symbol
// could compile oddly.
//
// Historically, we used static inline in headers. However, to satisfy ODR, use
// plain inline in C++, to allow inline consumer functions to call our header
// functions. Plain inline would also work better with C99 inline, but that is
// not used much in practice, extern inline is tedious, and there are conflicts
// with the old gnu89 model:
// https://stackoverflow.com/questions/216510/extern-inline
#if defined(__cplusplus)
#define OPENSSL_INLINE inline
#else
// Add OPENSSL_UNUSED so that, should an inline function be emitted via macro
// (e.g. a |STACK_OF(T)| implementation) in a source file without tripping
// clang's -Wunused-function.
#define OPENSSL_INLINE static inline OPENSSL_UNUSED
#endif

#if defined(OPENSSL_WINDOWS)
#define OPENSSL_NOINLINE __declspec(noinline)
#else
#define OPENSSL_NOINLINE __attribute__((noinline))
#endif

// ossl_ssize_t is a signed type which is large enough to fit the size of any
// valid memory allocation. We prefer using |size_t|, but sometimes we need a
// signed type for OpenSSL API compatibility. This type can be used in such
// cases to avoid overflow.
//
// Not all |size_t| values fit in |ossl_ssize_t|, but all |size_t| values that
// are sizes of or indices into C objects, can be converted without overflow.
typedef ptrdiff_t ossl_ssize_t;

// CBS_ASN1_TAG is the type used by |CBS| and |CBB| for ASN.1 tags. See that
// header for details. This type is defined in base.h as a forward declaration.
typedef uint32_t CBS_ASN1_TAG;

// CRYPTO_THREADID is a dummy value.
typedef int CRYPTO_THREADID;

// An |ASN1_NULL| is an opaque type. asn1.h represents the ASN.1 NULL value as
// an opaque, non-NULL |ASN1_NULL*| pointer.
typedef struct asn1_null_st ASN1_NULL;

typedef int ASN1_BOOLEAN;
typedef struct ASN1_ITEM_st ASN1_ITEM;
typedef struct asn1_object_st ASN1_OBJECT;
typedef struct asn1_pctx_st ASN1_PCTX;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_BMPSTRING;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_GENERALSTRING;
typedef struct asn1_string_st ASN1_IA5STRING;
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
typedef struct asn1_string_st ASN1_STRING;
typedef struct asn1_string_st ASN1_T61STRING;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_UTF8STRING;
typedef struct asn1_string_st ASN1_VISIBLESTRING;
typedef struct asn1_type_st ASN1_TYPE;
typedef struct AUTHORITY_KEYID_st AUTHORITY_KEYID;
typedef struct BASIC_CONSTRAINTS_st BASIC_CONSTRAINTS;
typedef struct DIST_POINT_st DIST_POINT;
typedef struct DSA_SIG_st DSA_SIG;
typedef struct GENERAL_NAME_st GENERAL_NAME;
typedef struct ISSUING_DIST_POINT_st ISSUING_DIST_POINT;
typedef struct NAME_CONSTRAINTS_st NAME_CONSTRAINTS;
typedef struct Netscape_spkac_st NETSCAPE_SPKAC;
typedef struct Netscape_spki_st NETSCAPE_SPKI;
typedef struct RIPEMD160state_st RIPEMD160_CTX;
typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM;
typedef struct X509_algor_st X509_ALGOR;
typedef struct X509_crl_st X509_CRL;
typedef struct X509_extension_st X509_EXTENSION;
typedef struct X509_info_st X509_INFO;
typedef struct X509_name_entry_st X509_NAME_ENTRY;
typedef struct X509_name_st X509_NAME;
typedef struct X509_pubkey_st X509_PUBKEY;
typedef struct X509_req_st X509_REQ;
typedef struct x509_sig_info_st X509_SIG_INFO;
typedef struct X509_sig_st X509_SIG;
typedef struct bignum_ctx BN_CTX;
typedef struct bignum_st BIGNUM;
typedef struct bio_method_st BIO_METHOD;
typedef struct bio_st BIO;
typedef struct blake2b_state_st BLAKE2B_CTX;
typedef struct bn_gencb_st BN_GENCB;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct buf_mem_st BUF_MEM;
typedef struct cast_key_st CAST_KEY;
typedef struct cbb_st CBB;
typedef struct cbs_st CBS;
typedef struct cmac_ctx_st CMAC_CTX;
typedef struct conf_st CONF;
typedef struct conf_value_st CONF_VALUE;
typedef struct crypto_buffer_pool_st CRYPTO_BUFFER_POOL;
typedef struct crypto_buffer_st CRYPTO_BUFFER;
typedef struct ctr_drbg_state_st CTR_DRBG_STATE;
typedef struct dh_st DH;
typedef struct dsa_st DSA;
typedef struct ec_group_st EC_GROUP;
typedef struct ec_key_st EC_KEY;
typedef struct ec_point_st EC_POINT;
typedef struct ec_key_method_st EC_KEY_METHOD;
typedef struct ecdsa_sig_st ECDSA_SIG;
typedef struct engine_st ENGINE;
typedef struct env_md_ctx_st EVP_MD_CTX;
typedef struct env_md_st EVP_MD;
typedef struct evp_aead_st EVP_AEAD;
typedef struct evp_aead_ctx_st EVP_AEAD_CTX;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_encode_ctx_st EVP_ENCODE_CTX;
typedef struct evp_hpke_aead_st EVP_HPKE_AEAD;
typedef struct evp_hpke_ctx_st EVP_HPKE_CTX;
typedef struct evp_hpke_kdf_st EVP_HPKE_KDF;
typedef struct evp_hpke_kem_st EVP_HPKE_KEM;
typedef struct evp_hpke_key_st EVP_HPKE_KEY;
typedef struct evp_kem_st EVP_KEM;
typedef struct kem_key_st KEM_KEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_signature_context_params_st EVP_PKEY_CTX_SIGNATURE_CONTEXT_PARAMS;
typedef struct hmac_ctx_st HMAC_CTX;
typedef struct md4_state_st MD4_CTX;
typedef struct md5_state_st MD5_CTX;
typedef struct pqdsa_key_st PQDSA_KEY;
typedef struct ocsp_req_ctx_st OCSP_REQ_CTX;
typedef struct ossl_init_settings_st OPENSSL_INIT_SETTINGS;
typedef struct pkcs7_digest_st PKCS7_DIGEST;
typedef struct pkcs7_enc_content_st PKCS7_ENC_CONTENT;
typedef struct pkcs7_encrypt_st PKCS7_ENCRYPT;
typedef struct pkcs7_envelope_st PKCS7_ENVELOPE;
typedef struct pkcs7_issuer_and_serial_st PKCS7_ISSUER_AND_SERIAL;
typedef struct pkcs7_recip_info_st PKCS7_RECIP_INFO;
typedef struct pkcs7_sign_envelope_st PKCS7_SIGN_ENVELOPE;
typedef struct pkcs7_signed_st PKCS7_SIGNED;
typedef struct pkcs7_signer_info_st PKCS7_SIGNER_INFO;
typedef struct pkcs7_st PKCS7;
typedef struct pkcs12_st PKCS12;
typedef struct pkcs8_priv_key_info_st PKCS8_PRIV_KEY_INFO;
typedef struct private_key_st X509_PKEY;
typedef struct rand_meth_st RAND_METHOD;
typedef struct rc4_key_st RC4_KEY;
typedef struct rsa_meth_st RSA_METHOD;
typedef struct rsassa_pss_params_st RSASSA_PSS_PARAMS;
typedef struct rsa_pss_params_st RSA_PSS_PARAMS;
typedef struct rsa_st RSA;
typedef struct sha256_state_st SHA256_CTX;
typedef struct sha512_state_st SHA512_CTX;
typedef struct sha_state_st SHA_CTX;
typedef struct spake2_ctx_st SPAKE2_CTX;
typedef struct srtp_protection_profile_st SRTP_PROTECTION_PROFILE;
typedef struct ssl_cipher_st SSL_CIPHER;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_early_callback_ctx SSL_CLIENT_HELLO;
typedef struct ssl_ech_keys_st SSL_ECH_KEYS;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_private_key_method_st SSL_PRIVATE_KEY_METHOD;
typedef struct ssl_quic_method_st SSL_QUIC_METHOD;
typedef struct ssl_session_st SSL_SESSION;
typedef struct ssl_st SSL;
typedef struct ssl_ticket_aead_method_st SSL_TICKET_AEAD_METHOD;
typedef struct st_ERR_FNS ERR_FNS;
typedef struct trust_token_st TRUST_TOKEN;
typedef struct trust_token_client_st TRUST_TOKEN_CLIENT;
typedef struct trust_token_issuer_st TRUST_TOKEN_ISSUER;
typedef struct trust_token_method_st TRUST_TOKEN_METHOD;
typedef struct v3_ext_ctx X509V3_CTX;
typedef struct v3_ext_method X509V3_EXT_METHOD;
typedef struct x509_attributes_st X509_ATTRIBUTE;
typedef struct x509_lookup_st X509_LOOKUP;
typedef struct x509_lookup_method_st X509_LOOKUP_METHOD;
typedef struct x509_object_st X509_OBJECT;
typedef struct x509_revoked_st X509_REVOKED;
typedef struct x509_st X509;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct x509_store_st X509_STORE;
typedef struct x509_trust_st X509_TRUST;

typedef void *OPENSSL_BLOCK;

// BSSL_CHECK aborts if |condition| is not true.
#define BSSL_CHECK(condition) \
  do {                        \
    if (!(condition)) {       \
      abort();                \
    }                         \
  } while (0);

#if defined(__cplusplus)
}  // extern C
#elif !defined(BORINGSSL_NO_CXX)
#define BORINGSSL_NO_CXX
#endif

#if defined(BORINGSSL_PREFIX)
#define BSSL_NAMESPACE_BEGIN \
  namespace bssl {           \
  inline namespace BORINGSSL_PREFIX {
#define BSSL_NAMESPACE_END \
  }                        \
  }
#else
#define BSSL_NAMESPACE_BEGIN namespace bssl {
#define BSSL_NAMESPACE_END }
#endif

// MSVC doesn't set __cplusplus to 201103 to indicate C++11 support (see
// https://connect.microsoft.com/VisualStudio/feedback/details/763051/a-value-of-predefined-macro-cplusplus-is-still-199711l)
// so MSVC is just assumed to support C++11.
#if !defined(BORINGSSL_NO_CXX) && __cplusplus < 201103L && !defined(_MSC_VER)
#define BORINGSSL_NO_CXX
#endif

#if !defined(BORINGSSL_NO_CXX)

extern "C++" {

#include <memory>

// STLPort, used by some Android consumers, not have std::unique_ptr.
#if defined(_STLPORT_VERSION)
#define BORINGSSL_NO_CXX
#endif

}  // extern C++
#endif  // !BORINGSSL_NO_CXX

#if defined(BORINGSSL_NO_CXX)

#define BORINGSSL_MAKE_DELETER(type, deleter)
#define BORINGSSL_MAKE_UP_REF(type, up_ref_func)

#else

extern "C++" {

BSSL_NAMESPACE_BEGIN

namespace internal {

// The Enable parameter is ignored and only exists so specializations can use
// SFINAE.
template <typename T, typename Enable = void>
struct DeleterImpl {};

struct Deleter {
  template <typename T>
  void operator()(T *ptr) {
    // Rather than specialize Deleter for each type, we specialize
    // DeleterImpl. This allows bssl::UniquePtr<T> to be used while only
    // including base.h as long as the destructor is not emitted. This matches
    // std::unique_ptr's behavior on forward-declared types.
    //
    // DeleterImpl itself is specialized in the corresponding module's header
    // and must be included to release an object. If not included, the compiler
    // will error that DeleterImpl<T> does not have a method Free.
    DeleterImpl<T>::Free(ptr);
  }
};

template <typename T, typename CleanupRet, void (*init)(T *),
          CleanupRet (*cleanup)(T *)>
class StackAllocated {
 public:
  StackAllocated() { init(&ctx_); }
  ~StackAllocated() { cleanup(&ctx_); }

  StackAllocated(const StackAllocated &) = delete;
  StackAllocated& operator=(const StackAllocated &) = delete;

  T *get() { return &ctx_; }
  const T *get() const { return &ctx_; }

  T *operator->() { return &ctx_; }
  const T *operator->() const { return &ctx_; }

  void Reset() {
    cleanup(&ctx_);
    init(&ctx_);
  }

 private:
  T ctx_;
};

template <typename T, typename CleanupRet, void (*init)(T *),
          CleanupRet (*cleanup)(T *), void (*move)(T *, T *)>
class StackAllocatedMovable {
 public:
  StackAllocatedMovable() { init(&ctx_); }
  ~StackAllocatedMovable() { cleanup(&ctx_); }

  StackAllocatedMovable(StackAllocatedMovable &&other) {
    init(&ctx_);
    move(&ctx_, &other.ctx_);
  }
  StackAllocatedMovable &operator=(StackAllocatedMovable &&other) {
    move(&ctx_, &other.ctx_);
    return *this;
  }

  T *get() { return &ctx_; }
  const T *get() const { return &ctx_; }

  T *operator->() { return &ctx_; }
  const T *operator->() const { return &ctx_; }

  void Reset() {
    cleanup(&ctx_);
    init(&ctx_);
  }

 private:
  T ctx_;
};

}  // namespace internal

#define BORINGSSL_MAKE_DELETER(type, deleter)     \
  namespace internal {                            \
  template <>                                     \
  struct DeleterImpl<type> {                      \
    static void Free(type *ptr) { deleter(ptr); } \
  };                                              \
  }

// Holds ownership of heap-allocated BoringSSL structures. Sample usage:
//   bssl::UniquePtr<RSA> rsa(RSA_new());
//   bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
template <typename T>
using UniquePtr = std::unique_ptr<T, internal::Deleter>;

#define BORINGSSL_MAKE_UP_REF(type, up_ref_func)             \
  inline UniquePtr<type> UpRef(type *v) {                    \
    if (v != nullptr) {                                      \
      up_ref_func(v);                                        \
    }                                                        \
    return UniquePtr<type>(v);                               \
  }                                                          \
                                                             \
  inline UniquePtr<type> UpRef(const UniquePtr<type> &ptr) { \
    return UpRef(ptr.get());                                 \
  }

BSSL_NAMESPACE_END

}  // extern C++

#endif  // !BORINGSSL_NO_CXX

#endif  // OPENSSL_HEADER_BASE_H
