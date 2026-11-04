__attribute__((noinline)) int padding(int x) {
    return x + 0x76543;
}

__attribute__((noinline)) int twin_one(int x) {
    return x * 257 + 0x12345;
}

__attribute__((noinline)) int twin_two(int x) {
    return x * 257 ^ 0x12345;
}

__attribute__((noinline)) int twin_identical(int x) {
    return x * 257 + 0x12345;
}

__attribute__((noinline)) int other_caller(int x) {
    return twin_one(x);
}

__attribute__((noinline)) int unique_copy(int x) {
    return x * 41 + 0x23457;
}

__attribute__((noinline)) int no_evidence_copy(int x) {
    return x;
}

int main(int argc, char **argv) {
    return other_caller(argc) == (argv == 0) || padding(argc) == 0 || unique_copy(argc) == no_evidence_copy(argc);
}
