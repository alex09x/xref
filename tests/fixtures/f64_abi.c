/*
 * XRef — x86-64 binary analysis and cross-reference tooling
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

/* SSE calling convention fixture: float parameters in xmm0..xmm7 and float returns in xmm0.
   Compiled with `cc -O2`; volatile inputs keep the calls from being folded. `log_msg` is variadic:
   its prologue spills xmm0..xmm7 into the register-save area, which are not float parameters. */

#include <stdarg.h>
#include <stdio.h>

__attribute__((noinline)) int log_msg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int written = vprintf(fmt, ap);
    va_end(ap);
    return written;
}

__attribute__((noinline)) int call_log(int x) {
    return log_msg("%d\n", x) + 1;
}

__attribute__((noinline)) double scale(double a, float b, long n) {
    return a * b * n;
}

__attribute__((noinline)) float halve(float x) {
    return x * 0.5f;
}

/* Float values crossing basic blocks: written before a branch, and returned by a call. */
__attribute__((noinline)) double branchy(double x, int n) {
    x = x * x;
    if (n)
        x += 3.0;
    return x;
}

__attribute__((noinline)) double after_call(double x, int n) {
    double y = scale(x, 2.0f, n);
    if (n > 1)
        y = y * x;
    return y;
}

/* void functions that leave the stored product in xmm0 at `ret` (`mulsd; movsd [rdi], xmm0; ret`):
   no caller reads it, so it is not a return value. noipa keeps GCC from cloning or reshaping them. */
__attribute__((noinline, noipa)) void store2(double *p, double x, double y) {
    *p = x * y;
}

__attribute__((noinline, noipa)) void store_f32(float *p, float x, float y) {
    *p = x * y;
}

/* A float result passed straight into a call through a function pointer: `call triple; call rax`. */
__attribute__((noinline, noipa)) double triple(double x) {
    return x * 3.0;
}

__attribute__((noinline, noipa)) double take(double x) {
    return x + 1.0;
}

double (*volatile take_ptr)(double) = take;

/* x86-64-v3 shapes: `a * b + c` contracts to `vfmadd`, `floor` inlines as `vroundsd`, a float
   compare is `vucomiss`, and `vxorps` zeroes the result between the `test` and its `je`. */
__attribute__((noinline, noipa)) double fused(double a, double b, double c) {
    return a * b + c;
}

#ifdef __SSE4_1__
__attribute__((noinline, noipa)) double floor_of(double x) {
    return __builtin_floor(x);
}
#endif

__attribute__((noinline, noipa)) float smaller(float x, float y) {
    return x < y ? x : y * 2.0f;
}

__attribute__((noinline, noipa)) double zero_unless(int n, double x) {
    return n ? x * x : 0.0;
}

int main(int argc, char **argv) {
    volatile double a = 1.5;
    volatile float b = 2.5f;
    volatile long n = argc;
    volatile double r = scale(a, b, n);
    volatile float h = halve(b);
    volatile double q = branchy(a, argc) + after_call(a, argc);
    double d;
    float f;
    /* Each store is followed directly by a call that takes no float argument: that call does not
       read the stored product left in xmm0. */
    store2(&d, a, a);
    int k = call_log(argc);
    store_f32(&f, b, b);
    k += call_log(argc + 1);
    volatile double t = take_ptr(triple(a));
    volatile double u = fused(a, a, a) + smaller(b, b) + zero_unless(argc, a);
#ifdef __SSE4_1__
    u += floor_of(a);
#endif
    (void)argv;
    return (int)(r + h + q + d + f + t + u) + k;
}
