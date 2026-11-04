/* Controlled native return-address capture. No production process is inspected. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static void (*volatile selected_leaf)(void);
static volatile unsigned sink;
static int burn;

__attribute__((noinline)) void trace_leaf(void) {
    if (burn) {
        for (unsigned i = 0; i < 20000; ++i) sink += i;
        return;
    }
    void *frames[24];
    int count = backtrace(frames, 24);
    for (int i = 0; i < count; ++i) printf("FRAME=%p\n", frames[i]);
    sink++;
}

__attribute__((noinline)) void trace_middle(void) {
    selected_leaf();
    __asm__ volatile(".globl trace_middle_return\ntrace_middle_return:" ::: "memory");
    sink++;
}

__attribute__((noinline)) void trace_entry(void) {
    trace_middle();
    __asm__ volatile(".globl trace_entry_return\ntrace_entry_return:" ::: "memory");
    sink++;
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc > 1) {
        burn = 1;
        selected_leaf = &trace_leaf;
        struct timespec begin, now;
        clock_gettime(CLOCK_MONOTONIC, &begin);
        do {
            trace_entry();
            clock_gettime(CLOCK_MONOTONIC, &now);
        } while ((now.tv_sec - begin.tv_sec) * 1000000000LL + now.tv_nsec - begin.tv_nsec < 1000000000LL);
        return 0;
    }
    Dl_info info;
    if (!dladdr((void *)&trace_entry, &info)) return 2;
    printf("BASE=%p\nPID=%d\n", info.dli_fbase, getpid());
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 3;
    char line[4096];
    while (fgets(line, sizeof line, maps)) printf("MAP=%s", line);
    fclose(maps);
    selected_leaf = &trace_leaf;
    trace_entry();
    return 0;
}
