// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Montgomery multiply, z := (x * y / 2^576) mod p_521
// Inputs x[9], y[9]; output z[9]
//
//    extern void bignum_montmul_p521_alt
//     (uint64_t z[static 9], uint64_t x[static 9], uint64_t y[static 9]);
//
// Does z := (x * y / 2^576) mod p_521, assuming x < p_521, y < p_521. This
// means the Montgomery base is the "native size" 2^{9*64} = 2^576; since
// p_521 is a Mersenne prime the basic modular multiplication bignum_mul_p521
// can be considered a Montgomery operation to base 2^521.
//
// Standard x86-64 ABI: RDI = z, RSI = x, RDX = y
// Microsoft x64 ABI:   RCX = z, RDX = x, R8 = y
// ----------------------------------------------------------------------------

#include "_internal_s2n_bignum.h"


        S2N_BN_SYM_VISIBILITY_DIRECTIVE(bignum_montmul_p521_alt)
        S2N_BN_SYM_PRIVACY_DIRECTIVE(bignum_montmul_p521_alt)
        .text

#define z %rdi
#define x %rsi

// This is moved from %rdx to free it for muls

#define y %rcx

// Macro for the key "multiply and add to (c,h,l)" step

#define combadd(c,h,l,numa,numb)                \
        movq    numa, %rax ;                      \
        mulq     numb;                 \
        addq    %rax, l ;                         \
        adcq    %rdx, h ;                         \
        adcq    $0, c

// A minutely shorter form for when c = 0 initially

#define combadz(c,h,l,numa,numb)                \
        movq    numa, %rax ;                      \
        mulq     numb;                 \
        addq    %rax, l ;                         \
        adcq    %rdx, h ;                         \
        adcq    c, c

// A short form where we don't expect a top carry

#define combads(h,l,numa,numb)                  \
        movq    numa, %rax ;                      \
        mulq     numb;                 \
        addq    %rax, l ;                         \
        adcq    %rdx, h

S2N_BN_SYMBOL(bignum_montmul_p521_alt):
        _CET_ENDBR

#if WINDOWS_ABI
        pushq   %rdi
        pushq   %rsi
        movq    %rcx, %rdi
        movq    %rdx, %rsi
        movq    %r8, %rdx
#endif

// Make more registers available and make temporary space on stack

        pushq   %r12
        pushq   %r13
        pushq   %r14
        pushq   %r15
        subq    $72, %rsp

// Copy y into a safe register to start with

        movq    %rdx, y

// Copy y into a safe register to start with

        mov %rdx, y

// Start doing a conventional columnwise multiplication,
// temporarily storing the lower 9 digits to the stack.
// Start with result term 0

        movq    (x), %rax
        mulq     (y)

        movq    %rax, (%rsp)
        movq    %rdx, %r9
        xorq    %r10, %r10

// Result term 1

        xorq    %r11, %r11
        combads(%r10,%r9,(x),8(y))
        combadz(%r11,%r10,%r9,8(x),(y))
        movq    %r9, 8(%rsp)

// Result term 2

        xorq    %r12, %r12
        combadz(%r12,%r11,%r10,(x),16(y))
        combadd(%r12,%r11,%r10,8(x),8(y))
        combadd(%r12,%r11,%r10,16(x),(y))
        movq    %r10, 16(%rsp)

// Result term 3

        xorq    %r13, %r13
        combadz(%r13,%r12,%r11,(x),24(y))
        combadd(%r13,%r12,%r11,8(x),16(y))
        combadd(%r13,%r12,%r11,16(x),8(y))
        combadd(%r13,%r12,%r11,24(x),(y))
        movq    %r11, 24(%rsp)

// Result term 4

        xorq    %r14, %r14
        combadz(%r14,%r13,%r12,(x),32(y))
        combadd(%r14,%r13,%r12,8(x),24(y))
        combadd(%r14,%r13,%r12,16(x),16(y))
        combadd(%r14,%r13,%r12,24(x),8(y))
        combadd(%r14,%r13,%r12,32(x),(y))
        movq    %r12, 32(%rsp)

// Result term 5

        xorq    %r15, %r15
        combadz(%r15,%r14,%r13,(x),40(y))
        combadd(%r15,%r14,%r13,8(x),32(y))
        combadd(%r15,%r14,%r13,16(x),24(y))
        combadd(%r15,%r14,%r13,24(x),16(y))
        combadd(%r15,%r14,%r13,32(x),8(y))
        combadd(%r15,%r14,%r13,40(x),(y))
        movq    %r13, 40(%rsp)

// Result term 6

        xorq    %r8, %r8
        combadz(%r8,%r15,%r14,(x),48(y))
        combadd(%r8,%r15,%r14,8(x),40(y))
        combadd(%r8,%r15,%r14,16(x),32(y))
        combadd(%r8,%r15,%r14,24(x),24(y))
        combadd(%r8,%r15,%r14,32(x),16(y))
        combadd(%r8,%r15,%r14,40(x),8(y))
        combadd(%r8,%r15,%r14,48(x),(y))
        movq    %r14, 48(%rsp)

// Result term 7

        xorq    %r9, %r9
        combadz(%r9,%r8,%r15,(x),56(y))
        combadd(%r9,%r8,%r15,8(x),48(y))
        combadd(%r9,%r8,%r15,16(x),40(y))
        combadd(%r9,%r8,%r15,24(x),32(y))
        combadd(%r9,%r8,%r15,32(x),24(y))
        combadd(%r9,%r8,%r15,40(x),16(y))
        combadd(%r9,%r8,%r15,48(x),8(y))
        combadd(%r9,%r8,%r15,56(x),(y))
        movq    %r15, 56(%rsp)

// Result term 8

        xorq    %r10, %r10
        combadz(%r10,%r9,%r8,(x),64(y))
        combadd(%r10,%r9,%r8,8(x),56(y))
        combadd(%r10,%r9,%r8,16(x),48(y))
        combadd(%r10,%r9,%r8,24(x),40(y))
        combadd(%r10,%r9,%r8,32(x),32(y))
        combadd(%r10,%r9,%r8,40(x),24(y))
        combadd(%r10,%r9,%r8,48(x),16(y))
        combadd(%r10,%r9,%r8,56(x),8(y))
        combadd(%r10,%r9,%r8,64(x),(y))
        movq    %r8, 64(%rsp)

// At this point we suspend writing back results and collect them
// in a register window. Next is result term 9

        xorq    %r11, %r11
        combadz(%r11,%r10,%r9,8(x),64(y))
        combadd(%r11,%r10,%r9,16(x),56(y))
        combadd(%r11,%r10,%r9,24(x),48(y))
        combadd(%r11,%r10,%r9,32(x),40(y))
        combadd(%r11,%r10,%r9,40(x),32(y))
        combadd(%r11,%r10,%r9,48(x),24(y))
        combadd(%r11,%r10,%r9,56(x),16(y))
        combadd(%r11,%r10,%r9,64(x),8(y))

// Result term 10

        xorq    %r12, %r12
        combadz(%r12,%r11,%r10,16(x),64(y))
        combadd(%r12,%r11,%r10,24(x),56(y))
        combadd(%r12,%r11,%r10,32(x),48(y))
        combadd(%r12,%r11,%r10,40(x),40(y))
        combadd(%r12,%r11,%r10,48(x),32(y))
        combadd(%r12,%r11,%r10,56(x),24(y))
        combadd(%r12,%r11,%r10,64(x),16(y))

// Result term 11

        xorq    %r13, %r13
        combadz(%r13,%r12,%r11,24(x),64(y))
        combadd(%r13,%r12,%r11,32(x),56(y))
        combadd(%r13,%r12,%r11,40(x),48(y))
        combadd(%r13,%r12,%r11,48(x),40(y))
        combadd(%r13,%r12,%r11,56(x),32(y))
        combadd(%r13,%r12,%r11,64(x),24(y))

// Result term 12

        xorq    %r14, %r14
        combadz(%r14,%r13,%r12,32(x),64(y))
        combadd(%r14,%r13,%r12,40(x),56(y))
        combadd(%r14,%r13,%r12,48(x),48(y))
        combadd(%r14,%r13,%r12,56(x),40(y))
        combadd(%r14,%r13,%r12,64(x),32(y))

// Result term 13

        xorq    %r15, %r15
        combadz(%r15,%r14,%r13,40(x),64(y))
        combadd(%r15,%r14,%r13,48(x),56(y))
        combadd(%r15,%r14,%r13,56(x),48(y))
        combadd(%r15,%r14,%r13,64(x),40(y))

// Result term 14

        xorq    %r8, %r8
        combadz(%r8,%r15,%r14,48(x),64(y))
        combadd(%r8,%r15,%r14,56(x),56(y))
        combadd(%r8,%r15,%r14,64(x),48(y))

// Result term 15

        combads(%r8,%r15,56(x),64(y))
        combads(%r8,%r15,64(x),56(y))

// Result term 16

        movq    64(x), %rax
        imulq   64(y), %rax
        addq    %r8, %rax

// Now the upper portion is [%rax;%r15;%r14;%r13;%r12;%r11;%r10;%r9;[%rsp+64]].
// Rotate the upper portion right 9 bits since 2^512 == 2^-9 (mod p_521)
// Let rotated result %rdx,%r15,%r14,...,%r8 be h (high) and %rsp[0..7] be l (low)

        movq    64(%rsp), %r8
        movq    %r8, %rdx
        andq    $0x1FF, %rdx
        shrdq   $9, %r9, %r8
        shrdq   $9, %r10, %r9
        shrdq   $9, %r11, %r10
        shrdq   $9, %r12, %r11
        shrdq   $9, %r13, %r12
        shrdq   $9, %r14, %r13
        shrdq   $9, %r15, %r14
        shrdq   $9, %rax, %r15
        shrq    $9, %rax
        addq    %rax, %rdx

// Force carry-in then add to get s = h + l + 1
// but actually add all 1s in the top 53 bits to get simple carry out

        stc
        adcq    (%rsp), %r8
        adcq    8(%rsp), %r9
        adcq    16(%rsp), %r10
        adcq    24(%rsp), %r11
        adcq    32(%rsp), %r12
        adcq    40(%rsp), %r13
        adcq    48(%rsp), %r14
        adcq    56(%rsp), %r15
        adcq    $~0x1FF, %rdx

// Now CF is set <=> h + l + 1 >= 2^521 <=> h + l >= p_521,
// in which case the lower 521 bits are already right. Otherwise if
// CF is clear, we want to subtract 1. Hence subtract the complement
// of the carry flag then mask the top word, which scrubs the
// padding in either case.

        cmc
        sbbq    $0, %r8
        sbbq    $0, %r9
        sbbq    $0, %r10
        sbbq    $0, %r11
        sbbq    $0, %r12
        sbbq    $0, %r13
        sbbq    $0, %r14
        sbbq    $0, %r15
        sbbq    $0, %rdx
        andq    $0x1FF, %rdx

// So far, this has been the same as a pure modular multiply.
// Now finally the Montgomery ingredient, which is just a 521-bit
// rotation by 9*64 - 521 = 55 bits right. Write digits back as
// they are created.

        movq    %r8, %rax
        shrdq   $55, %r9, %r8
        movq    %r8, (z)
        shrdq   $55, %r10, %r9
        movq    %r9, 8(z)
        shrdq   $55, %r11, %r10
        shlq    $9, %rax
        movq    %r10, 16(z)
        shrdq   $55, %r12, %r11
        movq    %r11, 24(z)
        shrdq   $55, %r13, %r12
        movq    %r12, 32(z)
        orq     %rax, %rdx
        shrdq   $55, %r14, %r13
        movq    %r13, 40(z)
        shrdq   $55, %r15, %r14
        movq    %r14, 48(z)
        shrdq   $55, %rdx, %r15
        movq    %r15, 56(z)
        shrq    $55, %rdx
        movq    %rdx, 64(z)

// Restore registers and return

        addq    $72, %rsp
        popq    %r15
        popq    %r14
        popq    %r13
        popq    %r12
#if WINDOWS_ABI
        popq   %rsi
        popq   %rdi
#endif
        ret

#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
