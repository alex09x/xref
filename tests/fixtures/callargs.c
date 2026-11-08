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

NOINLINE void produce13(struct Status *out, void *ctx) { h(out, ctx, 1, 2, 3, 13); }
NOINLINE void produce15(struct Status *out, void *ctx) { h(out, ctx, 4, 5, 6, 15); }
NOINLINE void produce16(struct Status *out, void *ctx) { h(out, ctx, 7, 8, 9, 16); }
NOINLINE void produce39(struct Status *out, void *ctx) { h(out, ctx, 10, 11, 12, 39); }
NOINLINE void produce38(struct Status *out, long value) { forward(out, value, 38); }

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

int main(int argc, char **argv) {
    struct Status status = {0, 0};
    switch (argc) {
        case 1: produce13(&status, argv); break;
        case 2: produce15(&status, argv); break;
        case 3: produce16(&status, argv); break;
        case 4: produce38(&status, argc); break;
        default: produce39(&status, argv); break;
    }
    return describe(&status)[0];
}
