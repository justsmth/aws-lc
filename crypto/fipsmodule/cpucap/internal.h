#ifndef OPENSSL_HEADER_CPUCAP_INTERNAL_H
#define OPENSSL_HEADER_CPUCAP_INTERNAL_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64) || defined(OPENSSL_ARM) || \
    defined(OPENSSL_AARCH64) || defined(OPENSSL_PPC64LE)
// OPENSSL_cpuid_setup initializes the platform-specific feature cache.
void OPENSSL_cpuid_setup(void);
#endif

// Runtime CPU feature support

#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
// OPENSSL_ia32cap_P contains the Intel CPUID bits when running on an x86 or
// x86-64 system.
//
//   Index 0:
//     EDX for CPUID where EAX = 1
//     Bit 20 is always zero
//     Bit 28 is adjusted to reflect whether the data cache is shared between
//       multiple logical cores
//     Bit 30 is used to indicate an Intel CPU
//   Index 1:
//     ECX for CPUID where EAX = 1
//     Bit 11 is used to indicate AMD XOP support, not SDBG
//   Index 2:
//     EBX for CPUID where EAX = 7
//   Index 3:
//     ECX for CPUID where EAX = 7
//
// Note: the CPUID bits are pre-adjusted for the OSXSAVE bit and the YMM and XMM
// bits in XCR0, so it is not necessary to check those.
extern uint32_t OPENSSL_ia32cap_P[4];

#if defined(BORINGSSL_FIPS) && !defined(BORINGSSL_SHARED_LIBRARY)
// The FIPS module, as a static library, requires an out-of-line version of
// |OPENSSL_ia32cap_get| so accesses can be rewritten by delocate. Mark the
// function const so multiple accesses can be optimized together.
const uint32_t *OPENSSL_ia32cap_get(void) __attribute__((const));
#else
OPENSSL_INLINE const uint32_t *OPENSSL_ia32cap_get(void) {
  CRYPTO_library_init();
  return OPENSSL_ia32cap_P;
}
#endif

OPENSSL_INLINE int OPENSSL_ia32cap_has_bit(int idx, int bit) {
  return (OPENSSL_ia32cap_get()[idx] & (1u << bit)) != 0;
}

// See Intel manual, volume 2A, table 3-11.

OPENSSL_INLINE int CRYPTO_is_FXSR_capable(void) {
#if defined(__FXSR__)
  return 1;
#else
  return OPENSSL_ia32cap_has_bit(/*idx=*/0, /*bit=*/24);
#endif
}

OPENSSL_INLINE int CRYPTO_is_intel_cpu(void) {
  // The reserved bit 30 is used to indicate an Intel CPU.
  return OPENSSL_ia32cap_has_bit(/*idx=*/0, /*bit=*/30);
}

// See Intel manual, volume 2A, table 3-10.

OPENSSL_INLINE int CRYPTO_is_PCLMUL_capable(void) {
#if defined(__PCLMUL__)
  return 1;
#else
  return OPENSSL_ia32cap_has_bit(/*idx=*/1, /*bit=*/1);
#endif
}

OPENSSL_INLINE int CRYPTO_is_SSSE3_capable(void) {
#if defined(__SSSE3__)
  return 1;
#else
  return OPENSSL_ia32cap_has_bit(/*idx=*/1, /*bit=*/9);
#endif
}

OPENSSL_INLINE int CRYPTO_is_SSE4_1_capable(void) {
#if defined(__SSE4_1__)
  return 1;
#else
  return OPENSSL_ia32cap_has_bit(/*idx=*/1, /*bit=*/19);
#endif
}

OPENSSL_INLINE int CRYPTO_is_MOVBE_capable(void) {
#if defined(__MOVBE__)
  return 1;
#else
  return OPENSSL_ia32cap_has_bit(/*idx=*/1, /*bit=*/22);
#endif
}

OPENSSL_INLINE int CRYPTO_is_AESNI_capable(void) {
#if defined(__AES__)
  return 1;
#else
  return OPENSSL_ia32cap_has_bit(/*idx=*/1, /*bit=*/25);
#endif
}

OPENSSL_INLINE int CRYPTO_is_AVX_capable(void) {
#if defined(__AVX__)
  return 1;
#else
  return OPENSSL_ia32cap_has_bit(/*idx=*/1, /*bit=*/28);
#endif
}

OPENSSL_INLINE int CRYPTO_is_RDRAND_capable(void) {
  // The GCC/Clang feature name and preprocessor symbol for RDRAND are "rdrnd"
  // and |__RDRND__|, respectively.
#if defined(__RDRND__)
  return 1;
#else
  return OPENSSL_ia32cap_has_bit(/*idx=*/1, /*bit=*/30);
#endif
}

OPENSSL_INLINE int CRYPTO_is_AMD_XOP_support(void) {
  #if defined(__XOP__)
    return 1;
  #else
    return OPENSSL_ia32cap_has_bit(/*idx=*/1, /*bit=*/11);
  #endif
}

// See Intel manual, volume 2A, table 3-8.

OPENSSL_INLINE int CRYPTO_is_BMI1_capable(void) {
#if defined(__BMI1__)
  return 1;
#else
  return OPENSSL_ia32cap_has_bit(/*idx=*/2, /*bit=*/3);
#endif
}

OPENSSL_INLINE int CRYPTO_is_AVX2_capable(void) {
#if defined(__AVX2__)
  return 1;
#else
  return OPENSSL_ia32cap_has_bit(/*idx=*/2, /*bit=*/5);
#endif
}

OPENSSL_INLINE int CRYPTO_is_BMI2_capable(void) {
#if defined(__BMI2__)
  return 1;
#else
  return OPENSSL_ia32cap_has_bit(/*idx=*/2, /*bit=*/8);
#endif
}

OPENSSL_INLINE int CRYPTO_is_ADX_capable(void) {
#if defined(__ADX__)
  return 1;
#else
  return OPENSSL_ia32cap_has_bit(/*idx=*/2, /*bit=*/19);
#endif
}

OPENSSL_INLINE int CRYPTO_is_SHAEXT_capable(void) {
  return OPENSSL_ia32cap_has_bit(/*idx=*/2, /*bit=*/29);
}

OPENSSL_INLINE int CRYPTO_is_AVX512_capable(void) {
  return (OPENSSL_ia32cap_get()[2] & 0xC0030000) == 0xC0030000;
}

OPENSSL_INLINE int CRYPTO_is_VAES_capable(void) {
  return (OPENSSL_ia32cap_get()[3] & (1u << (41 - 32))) != 0;
}

OPENSSL_INLINE int CRYPTO_is_VPCLMULQDQ_capable(void) {
  return (OPENSSL_ia32cap_get()[3] & (1u << (42 - 32))) != 0;
}

OPENSSL_INLINE int CRYPTO_is_VBMI2_capable(void) {
  return OPENSSL_ia32cap_has_bit(/*idx=*/3, /*bit=*/6);
}


#endif  // OPENSSL_X86 || OPENSSL_X86_64

#if defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)

// We do not detect any features at runtime on several 32-bit Arm platforms.
// Apple platforms and OpenBSD require NEON and moved to 64-bit to pick up Armv8
// extensions. Android baremetal does not aim to support 32-bit Arm at all, but
// it simplifies things to make it build.
#if defined(OPENSSL_ARM) && !defined(OPENSSL_STATIC_ARMCAP) && \
    (defined(OPENSSL_APPLE) || defined(OPENSSL_OPENBSD) ||     \
     defined(ANDROID_BAREMETAL))
#define OPENSSL_STATIC_ARMCAP
#endif

// Normalize some older feature flags to their modern ACLE values.
// https://developer.arm.com/architectures/system-architectures/software-standards/acle
#if defined(__ARM_NEON__) && !defined(__ARM_NEON)
#define __ARM_NEON 1
#endif
#if defined(__ARM_FEATURE_CRYPTO)
#if !defined(__ARM_FEATURE_AES)
#define __ARM_FEATURE_AES 1
#endif
#if !defined(__ARM_FEATURE_SHA2)
#define __ARM_FEATURE_SHA2 1
#endif
#endif

#include <openssl/arm_arch.h>

extern uint32_t OPENSSL_armcap_P;
extern uint8_t OPENSSL_cpucap_initialized;

OPENSSL_INLINE uint32_t OPENSSL_get_armcap(void) {
  CRYPTO_library_init();
  return OPENSSL_armcap_P;
}

// CRYPTO_is_NEON_capable returns true if the current CPU has a NEON unit.
// If this is known statically, it is a constant inline function.
// Otherwise, the capability is checked at runtime by checking the corresponding
// bit in |OPENSSL_armcap_P|. This is also the same for
// |CRYPTO_is_ARMv8_AES_capable| and |CRYPTO_is_ARMv8_PMULL_capable|
// for checking the support for AES and PMULL instructions, respectively.
OPENSSL_INLINE int CRYPTO_is_NEON_capable(void) {
#if defined(OPENSSL_STATIC_ARMCAP_NEON) || defined(__ARM_NEON)
  return 1;
#elif defined(OPENSSL_STATIC_ARMCAP)
  return 0;
#else
  return (OPENSSL_get_armcap() & ARMV7_NEON) != 0;
#endif
}

OPENSSL_INLINE int CRYPTO_is_ARMv8_AES_capable(void) {
#if defined(OPENSSL_STATIC_ARMCAP_AES) || defined(__ARM_FEATURE_AES)
  return 1;
#elif defined(OPENSSL_STATIC_ARMCAP)
  return 0;
#else
  return (OPENSSL_get_armcap() & ARMV8_AES) != 0;
#endif
}

OPENSSL_INLINE int CRYPTO_is_ARMv8_PMULL_capable(void) {
#if defined(OPENSSL_STATIC_ARMCAP_PMULL) || defined(__ARM_FEATURE_AES)
  return 1;
#elif defined(OPENSSL_STATIC_ARMCAP)
  return 0;
#else
  return (OPENSSL_get_armcap() & ARMV8_PMULL) != 0;
#endif
}

OPENSSL_INLINE int CRYPTO_is_ARMv8_GCM_8x_capable(void) {
#if defined(OPENSSL_STATIC_ARMCAP)
  return 0;
#else
  return ((OPENSSL_get_armcap() & ARMV8_SHA3) != 0 &&
          ((OPENSSL_get_armcap() & ARMV8_NEOVERSE_V1) != 0 ||
           (OPENSSL_get_armcap() & ARMV8_APPLE_M1) != 0));
#endif
}

OPENSSL_INLINE int CRYPTO_is_ARMv8_wide_multiplier_capable(void) {
#if defined(OPENSSL_STATIC_ARMCAP)
  return 0;
#else
  return (OPENSSL_get_armcap() & ARMV8_NEOVERSE_V1) != 0 ||
           (OPENSSL_get_armcap() & ARMV8_APPLE_M1) != 0;
#endif
}

#endif  // OPENSSL_ARM || OPENSSL_AARCH64

#if defined(OPENSSL_PPC64LE)

// CRYPTO_is_PPC64LE_vcrypto_capable returns true iff the current CPU supports
// the Vector.AES category of instructions.
int CRYPTO_is_PPC64LE_vcrypto_capable(void);

extern unsigned long OPENSSL_ppc64le_hwcap2;

#endif  // OPENSSL_PPC64LE

#if defined(__cplusplus)
}
#endif

#endif // OPENSSL_HEADER_CPUCAP_INTERNAL_H
