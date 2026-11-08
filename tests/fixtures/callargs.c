/*
 * XRef — fixture for constant call arguments and tags passed to a helper (#151)
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

/* A status enum whose producers never store the tag themselves: they pass it to a helper
 * `h(out, ctx, i, a, b, status)` (status in r9), or to `forward`, which hands it to `store_tag`. */

struct Status {
    unsigned char tag;
    long value;
};

#include <string.h>

#define NOINLINE __attribute__((noinline))

NOINLINE void h(struct Status *out, void *ctx, long i, long a, long b, unsigned status) {
    out->tag = (unsigned char)status;
    out->value = a + b + i + (long)ctx;
}

NOINLINE void store_tag(struct Status *out, unsigned status) { out->tag = (unsigned char)status; }

NOINLINE void forward(struct Status *out, long value, unsigned status) {
    out->value = value;
    store_tag(out, status);
}

/* #162: an rbp-framed helper (built at -O0) spills the status to `[rbp-d]`, calls something,
 * reloads it and stores it into the caller's field. */
__attribute__((noinline, noipa)) void sink(void) { __asm__ volatile(""); }

__attribute__((noinline, optimize("O0"))) void spill_tag(struct Status *out, unsigned status) {
    sink();
    out->tag = (unsigned char)status;
}

NOINLINE void produce37(struct Status *out) { spill_tag(out, 37); }

/* #164: the tag is the 8th argument, in the second stack slot (`stack1`); the callee reads it
 * back from its incoming slot after a call and stores it into the field. */
NOINLINE void eight(struct Status *out, long a, long b, long c, long d, long e, long f, unsigned status) {
    sink();
    out->value = a + b + c + d + e + f;
    out->tag = (unsigned char)status;
}

NOINLINE void produce34(struct Status *out) { eight(out, 1, 2, 3, 4, 5, 6, 34); }

NOINLINE void produce13(struct Status *out, void *ctx) { h(out, ctx, 1, 2, 3, 13); }
NOINLINE void produce15(struct Status *out, void *ctx) { h(out, ctx, 4, 5, 6, 15); }
NOINLINE void produce16(struct Status *out, void *ctx) { h(out, ctx, 7, 8, 9, 16); }
NOINLINE void produce39(struct Status *out, void *ctx) { h(out, ctx, 10, 11, 12, 39); }
NOINLINE void produce38(struct Status *out, long value) { forward(out, value, 38); }

/* #163: the tag is stored into a 0x200-byte record built on the stack (its address escapes to
 * `fill`), the record is copied whole into the caller's buffer, and the caller's next callee
 * reads the tag there. */
struct Record {
    unsigned long head[8];
    unsigned char tag;
    unsigned char rest[0x200 - 0x41];
};

__attribute__((noinline, noipa)) void fill(struct Record *r) { r->head[0] = (unsigned long)r; }

NOINLINE void build(struct Record *out, unsigned status) {
    struct Record r;
    r.tag = (unsigned char)status;
    fill(&r);
    memcpy(out, &r, sizeof r);
}

NOINLINE int check(const struct Record *r) { return r->tag == 39; }

/* The same record pushed into a Vec-like array: the copy lands in a computed element, and the
 * reader is elsewhere, walking the elements. */
struct Records {
    unsigned long cap;
    struct Record *ptr;
    unsigned long len;
};

NOINLINE void push_record(struct Records *v, unsigned status) {
    struct Record r;
    r.tag = (unsigned char)status;
    fill(&r);
    memcpy(&v->ptr[v->len], &r, sizeof r);
    v->len += 1;
}

NOINLINE unsigned long count_restored(const struct Records *v) {
    unsigned long n = 0;
    for (unsigned long i = 0; i < v->len; i++)
        n += v->ptr[i].tag == 39;
    return n;
}

NOINLINE void produce_pushed(struct Records *v) { push_record(v, 36); }

NOINLINE int produce_record(struct Record *buf) {
    build(buf, 35);
    return check(buf);
}

#define ARM(n, text) \
    case n:          \
        return text;

NOINLINE const char *describe(const struct Status *status) {
    switch (status->tag) {
        ARM(0, "job 00 idle") ARM(1, "job 01 queued") ARM(2, "job 02 running") ARM(3, "job 03 paused")
        ARM(4, "job 04 finished") ARM(5, "job 05 timed out") ARM(6, "job 06 rejected: no worker")
        ARM(7, "job 07 rejected: bad input") ARM(8, "job 08 rejected: too large") ARM(9, "job 09 rejected: quota")
        ARM(10, "job 10 rejected: duplicate") ARM(11, "job 11 rejected: locked") ARM(12, "job 12 rejected: stale")
        ARM(13, "job 13 cancelled by user") ARM(14, "job 14 cancelled by admin")
        ARM(15, "job 15 cancelled on timeout") ARM(16, "job 16 cancelled on shutdown")
        ARM(17, "job 17 retried") ARM(18, "job 18 worker lost") ARM(19, "job 19 disk full")
        ARM(20, "job 20 network down") ARM(21, "job 21 account disabled") ARM(22, "job 22 project deleted")
        ARM(23, "job 23 memory limit") ARM(24, "job 24 missing artifact") ARM(25, "job 25 hook failed")
        ARM(26, "job 26 split") ARM(27, "job 27 merged") ARM(28, "job 28 scheduled")
        ARM(29, "job 29 waiting on parent") ARM(30, "job 30 waiting on lock")
        ARM(31, "job 31 bad token") ARM(32, "job 32 bad checksum") ARM(33, "job 33 bad config")
        ARM(34, "job 34 license expired") ARM(35, "job 35 mirror out of date") ARM(36, "job 36 child failed")
        ARM(37, "job 37 watchdog fired") ARM(38, "job 38 forwarded cancel")
        ARM(39, "job 39 sibling cancelled")
    }
    return "unknown job status";
}

NOINLINE const char *describe_record(const struct Record *record) {
    switch (record->tag) {
        ARM(30, "record 30 open") ARM(31, "record 31 sealed") ARM(32, "record 32 archived")
        ARM(33, "record 33 lost") ARM(34, "record 34 merged") ARM(35, "record 35 split")
        ARM(36, "record 36 locked") ARM(37, "record 37 copied out") ARM(38, "record 38 dropped")
        ARM(39, "record 39 restored")
    }
    return "unknown record";
}

struct Record record;

int main(int argc, char **argv) {
    if (argc > 6) {
        struct Records v = {1, &record, 0};
        produce_pushed(&v);
        return (int)count_restored(&v) + describe_record(v.ptr)[0];
    }
    if (argc > 5)
        return produce_record(&record) + describe_record(&record)[0];
    struct Status status = {0, 0};
    switch (argc) {
        case 1: produce13(&status, argv); break;
        case 2: produce15(&status, argv); break;
        case 3: produce16(&status, argv); break;
        case 4: produce38(&status, argc); break;
        case 5: produce37(&status); break;
        case 6: produce34(&status); break;
        default: produce39(&status, argv); break;
    }
    return describe(&status)[0];
}
