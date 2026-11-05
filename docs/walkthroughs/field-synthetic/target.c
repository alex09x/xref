#include <stdint.h>
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
