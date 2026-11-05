/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

__attribute__((used))
static const double powers[20] = {
    1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9,
    1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19
};

__attribute__((used))
const char test_string[] = "Hello, xref data reading!";

__attribute__((used))
long bss_array[16] = {0};

__attribute__((used, noinline))
double get_power(volatile int i) {
    return powers[i % 20];
}

__attribute__((used, noinline))
const char *get_string(void) {
    return test_string;
}

__attribute__((used, noinline))
long get_bss(volatile int i) {
    return bss_array[i % 16];
}

int main(int argc, char **argv) {
    (void)argv;
    return (int)(get_power(argc) + (double)get_string()[0] + (double)get_bss(argc));
}
