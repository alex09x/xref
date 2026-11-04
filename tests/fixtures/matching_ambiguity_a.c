__attribute__((noinline)) int target(int x) {
    return x * 257 + 0x12345;
}

__attribute__((noinline)) int caller(int x) {
    return target(x);
}

__attribute__((noinline)) int unique_target(int x) {
    return x * 41 + 0x23457;
}

__attribute__((noinline)) int no_evidence(int x) {
    return x;
}

int main(int argc, char **argv) {
    return caller(argc) == (argv == 0) || unique_target(argc) == no_evidence(argc);
}
