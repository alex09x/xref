/* Neutral CPU-bound multithreaded target for sampling integration tests. */
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static atomic_int running = 1;
static atomic_uint_fast64_t observed;
static atomic_uint_fast64_t completed;

__attribute__((noinline)) uint64_t profile_hot(uint64_t value) {
#ifdef PROFILE_FORCE_FRAME
    volatile uint64_t frame_anchor = value;
    value = frame_anchor;
#endif
    for (unsigned index = 0; index < 10000; ++index) {
        value = value * UINT64_C(6364136223846793005) + index;
    }
    return value;
}

static void *worker(void *arg) {
    uintptr_t seed = (uintptr_t)arg + 1;
    uint64_t rounds = 0;
    while (atomic_load_explicit(&running, memory_order_relaxed)) {
        seed = profile_hot(seed);
        atomic_store_explicit(&observed, seed, memory_order_relaxed);
        ++rounds;
    }
    atomic_fetch_add_explicit(&completed, rounds, memory_order_relaxed);
    return 0;
}

int main(int argc, char **argv) {
    unsigned long count = argc > 1 ? strtoul(argv[1], 0, 10) : 2;
    if (count == 0 || count > 64) return 1;
    pthread_t threads[64];
    for (uintptr_t index = 0; index < count; ++index) {
        if (pthread_create(&threads[index], 0, worker, (void *)index) != 0) return 1;
    }
    printf("READY pid=%ld\n", (long)getpid());
    fflush(stdout);
    (void)getchar();
    atomic_store_explicit(&running, 0, memory_order_relaxed);
    for (unsigned index = 0; index < count; ++index) pthread_join(threads[index], 0);
    if (argc > 2) printf("DONE operations=%llu\n", (unsigned long long)atomic_load_explicit(&completed, memory_order_relaxed));
    return 0;
}
