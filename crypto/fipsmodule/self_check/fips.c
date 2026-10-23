// Copyright (c) 2017, Google Inc.
// SPDX-License-Identifier: ISC

// Ensure we can't call OPENSSL_malloc
#define _BORINGSSL_PROHIBIT_OPENSSL_MALLOC
#include <openssl/crypto.h>

#include "../../internal.h"
#include "../delocate.h"

#include "../rand/entropy/internal.h"


#if defined(BORINGSSL_FIPS)

// fips_module_error_state is non-zero once any self-test, integrity test or
// pairwise consistency test has failed in this process. It is only ever set,
// never cleared: the module stays in the error state until the process exits.
DEFINE_BSS_GET(CRYPTO_atomic_u32, fips_module_error_state)

void AWS_LC_FIPS_enter_error_state(void) {
  CRYPTO_atomic_store_u32(fips_module_error_state_bss_get(), 1);
}

// Trampoline function to avoid ARM64 ADR range issues in large FIPS module.
// See |put_set_thread_local_error| in service_indicator.c.
static OPENSSL_NOINLINE void put_fips_module_error_state_error(void) {
  OPENSSL_PUT_ERROR(CRYPTO, ERR_R_FIPS_MODULE_ERROR_STATE);
}

int AWS_LC_FIPS_service_blocked(void) {
  if (!AWS_LC_fips_failure_detected()) {
    return 0;
  }
  put_fips_module_error_state_error();
  return 1;
}

#endif  // BORINGSSL_FIPS

int AWS_LC_fips_failure_detected(void) {
#if defined(BORINGSSL_FIPS)
  return CRYPTO_atomic_load_u32(fips_module_error_state_bss_get()) != 0;
#else
  return 0;
#endif
}

int FIPS_mode(void) {
#if defined(BORINGSSL_FIPS) && !defined(OPENSSL_ASAN) && !defined(OPENSSL_MSAN)
  // A module in the error state no longer provides approved services.
  return AWS_LC_fips_failure_detected() ? 0 : 1;
#else
  return 0;
#endif
}

int FIPS_is_entropy_cpu_jitter(void) {
  if (OPT_OUT_CPU_JITTER_ENTROPY_SOURCE == get_entropy_source_method_id_FOR_TESTING()) {
    return 0;
  }
  return 1;
}

uint32_t FIPS_version(void) {
#if defined(BORINGSSL_FIPS) && !defined(OPENSSL_ASAN) && !defined(OPENSSL_MSAN)
  return AWSLC_FIPS_VERSION_NUMBER;
#else
  return 0;
#endif
}

const char *FIPS_module_name(void) { return AWSLC_MODULE_NAME_STRING; }

int FIPS_mode_set(int on) { return on == FIPS_mode(); }
