// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Return size of bignum in digits (64-bit word)
// Input x[k]; output function return
//
//    extern uint64_t bignum_digitsize (uint64_t k, uint64_t *x);
//
// In the case of a zero bignum as input the result is 0
//
// Standard ARM ABI: X0 = k, X1 = x, returns X0
// ----------------------------------------------------------------------------
#include "_internal_s2n_bignum.h"

        S2N_BN_SYM_VISIBILITY_DIRECTIVE(bignum_digitsize)
        S2N_BN_SYM_PRIVACY_DIRECTIVE(bignum_digitsize)
        .text
        .balign 4

#define k x0
#define x x1
#define i x2
#define a x3
#define j x4


S2N_BN_SYMBOL(bignum_digitsize):

// If the bignum is zero-length, x0 is already the right answer of 0

        cbz     k, bignum_digitsize_end

// Run over the words j = 0..i-1, and set i := j + 1 when hitting nonzero a[j]

        mov     i, xzr
        mov     j, xzr
bignum_digitsize_loop:
        ldr     a, [x, j, lsl #3]
        add     j, j, #1
        cmp     a, #0
        csel    i, j, i, ne
        cmp     j, k
        bne     bignum_digitsize_loop

        mov     x0, i
bignum_digitsize_end:
        ret

#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
