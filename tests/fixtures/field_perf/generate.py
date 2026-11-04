#!/usr/bin/env python3
# XRef — executable analysis
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generate a neutral ELF benchmark with many unwind-indexed functions."""

import argparse
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--functions", type=int, default=65000)
    parser.add_argument("--padding", type=int, default=640)
    parser.add_argument("--writers", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    with (args.output / "bulk.S").open("w", encoding="utf-8") as source:
        source.write(".text\n")
        for index in range(args.functions):
            body = "movq %rsi, 8(%rdi)\nxorq %rdx, 16(%rdi)\nret\n" if args.writers else "ret\n"
            source.write(
                f".type fixture_{index},@function\nfixture_{index}:\n"
                ".cfi_startproc\n" + body +
                f".fill {args.padding},1,0x90\n.cfi_endproc\n"
                f".size fixture_{index},.-fixture_{index}\n"
            )
        source.write('.section .note.GNU-stack,"",@progbits\n')
    (args.output / "target.c").write_text(
        """#include <stdint.h>
struct record { uint64_t c, m, e; };
volatile uint64_t sink;
__attribute__((noinline, noipa)) void emit(const char *key, uint64_t length, const uint64_t *value) {
    sink ^= (uint64_t)key[0] + length + *value;
}
__attribute__((noinline)) void serializer(struct record *p) {
    emit("c", 1, &p->c); emit("m", 1, &p->m); emit("e", 1, &p->e);
}
__attribute__((noinline)) void writer(struct record *p, uint64_t value) {
    p->m += value; p->e ^= value;
}
int main(void) { struct record p = {1, 2, 3}; writer(&p, 4); serializer(&p); return (int)sink; }
""",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
