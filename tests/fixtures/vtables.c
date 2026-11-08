/*
 * XRef — fixture for indirect calls through constant vtables chosen by branch (#168)
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

/* Five static "trait objects": 32-byte vtables in .data.rel.ro whose function pointers a PIE
 * fills with R_X86_64_RELATIVE relocations. `dispatch` picks one per branch and calls its fourth
 * slot (+0x18), like a Rust `&dyn Trait` method call. */

struct VTable {
    void (*drop)(void *);
    unsigned long size;
    unsigned long align;
    int (*call)(void *, int);
};

#define NOINLINE __attribute__((noinline))

NOINLINE int add_one(void *self, int x) { return x + 1 + (self != 0); }
NOINLINE int double_it(void *self, int x) { return 2 * x + (self != 0); }
NOINLINE int negate(void *self, int x) { return -x + (self != 0); }
NOINLINE int square(void *self, int x) { return x * x + (self != 0); }
NOINLINE int keep(void *self, int x) { return x + (self != 0); }

static const struct VTable V0 = {0, 8, 8, add_one};
static const struct VTable V1 = {0, 8, 8, double_it};
static const struct VTable V2 = {0, 8, 8, negate};
static const struct VTable V3 = {0, 8, 8, square};
static const struct VTable V4 = {0, 8, 8, keep};

NOINLINE int dispatch(int which, void *self, int x) {
    /* The empty asm makes each vtable pointer opaque, as a `&dyn Trait` vtable is to the caller:
     * the call goes through its +0x18 slot instead of being devirtualized. */
    const struct VTable *v;
    if (which == 10) {
        v = &V0;
        __asm__("" : "+r"(v));
    } else if (which == 20) {
        v = &V1;
        __asm__("" : "+r"(v));
    } else if (which == 30) {
        v = &V2;
        __asm__("" : "+r"(v));
    } else if (which == 40) {
        v = &V3;
        __asm__("" : "+r"(v));
    } else {
        v = &V4;
        __asm__("" : "+r"(v));
    }
    return v->call(self, x) + 1;
}

/* Its address, so `table` can be pointed at the first vtable. */
const struct VTable *const first_vtable = &V0;

int main(int argc, char **argv) { return dispatch(argc * 10, argv, argc) + (first_vtable != 0); }
