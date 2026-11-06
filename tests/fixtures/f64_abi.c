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

int main(int argc, char **argv) {
    volatile double a = 1.5;
    volatile float b = 2.5f;
    volatile long n = argc;
    volatile double r = scale(a, b, n);
    volatile float h = halve(b);
    (void)argv;
    return (int)(r + h) + call_log(argc);
}
