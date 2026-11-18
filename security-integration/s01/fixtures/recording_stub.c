/* SPDX-License-Identifier: Apache-2.0 */
/* Synthetic qualification fixture, never a third-party scanner. */
typedef unsigned long usize;

static long call6(long number, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory", "cc");
    return result;
}

static usize length(const char *s) { usize n = 0; while (s[n]) n++; return n; }
static int equal(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}
static __attribute__((noreturn)) void finish(int code) { call6(60, code, 0, 0, 0, 0, 0); for (;;) {} }
static void emit(const char *s) {
    usize remaining = length(s);
    while (remaining) {
        long n = call6(1, 1, (long)s, remaining, 0, 0, 0);
        if (n <= 0) finish(91);
        s += n; remaining -= n;
    }
}
static long open_file(const char *name, long flags) { return call6(257, -100, (long)name, flags, 0600, 0, 0); }
static void require(int predicate) { if (!predicate) { emit("FIXTURE_FAILED\n"); finish(90); } }
static char buffer[4096];

static void record(long argc, char **argv) {
    for (long i = 2; i < argc; i++) {
        long fd = open_file(argv[i], 0);
        require(fd >= 0);
        emit("INPUT\n");
        for (;;) {
            long n = call6(0, fd, (long)buffer, sizeof(buffer), 0, 0, 0);
            require(n >= 0);
            if (n == 0) break;
            long offset = 0;
            while (offset < n) {
                long written = call6(1, 1, (long)(buffer + offset), n - offset, 0, 0, 0);
                require(written > 0); offset += written;
            }
        }
        require(call6(3, fd, 0, 0, 0, 0, 0) == 0);
    }
}

static void containment(long argc, char **argv, char **env) {
    const char *allowed[] = {"LANG=C", "LC_ALL=C", "HOME=/nonexistent", "TMPDIR=/output", "PWD=/output"};
    long count = 0;
    unsigned seen_environment = 0;
    for (; env[count]; count++) {
        int found = 0;
        for (long j = 0; j < 5; j++) if (equal(env[count], allowed[j])) {
            require(!(seen_environment & (1u << j)));
            seen_environment |= 1u << j; found++;
        }
        require(found == 1 && count < 5);
    }
    require(count == 5 && seen_environment == 31);
    char info[256];
    for (long fd = 0; fd < 32; fd++) {
        long result = call6(5, fd, (long)info, 0, 0, 0, 0);
        require(fd < 3 ? result == 0 : result == -9);
    }
    require(call6(39, 0, 0, 0, 0, 0, 0) == 1);
    require(call6(110, 0, 0, 0, 0, 0, 0) == 0);
    const char *absent[] = {"/etc/passwd", "/proc/self/environ", "/sys", "/dev", "/root", "/home", "/outside"};
    for (long i = 0; i < 7; i++) require(open_file(absent[i], 0) < 0);
    for (long i = 2; i < argc; i++) require(open_file(argv[i], 1) < 0);
    require(open_file("/tool", 1) < 0);
    require(open_file("/output/new", 65) == -1);
    require(open_file("/output", 0x410002) == -1);
    require(call6(83, (long)"/output/newdir", 0700, 0, 0, 0, 0) == -1);
    require(call6(87, (long)"/output/result.bin", 0, 0, 0, 0, 0) == -1);
    require(call6(82, (long)"/output/result.bin", (long)"/output/new", 0, 0, 0, 0) == -1);
    require(call6(88, (long)"/tool", (long)"/output/link", 0, 0, 0, 0) == -1);
    require(call6(90, (long)"/output/result.bin", 0700, 0, 0, 0, 0) == -1);
    require(call6(41, 2, 1, 0, 0, 0, 0) == -1);
    require(call6(53, 1, 1, 0, (long)info, 0, 0) == -1);
    require(call6(56, 0, 0, 0, 0, 0, 0) == -1);
    require(call6(57, 0, 0, 0, 0, 0, 0) == -1);
    require(call6(58, 0, 0, 0, 0, 0, 0) == -1);
    require(call6(435, 0, 0, 0, 0, 0, 0) == -1);
    require(call6(272, 0, 0, 0, 0, 0, 0) == -1);
    require(call6(165, 0, 0, 0, 0, 0, 0) == -1);
    require(call6(101, 0, 0, 0, 0, 0, 0) == -1);
    require(call6(135, 0xffffffff, 0, 0, 0, 0, 0) == -1);
    require(call6(319, (long)"new", 0, 0, 0, 0, 0) == -1);
    require(call6(9, 0, 4096, 7, 0x22, -1, 0) == -1);
    long memory = call6(9, 0, 4096, 3, 0x22, -1, 0);
    require(memory > 0);
    require(call6(10, memory, 4096, 5, 0, 0, 0) == -1);
    require(call6(11, memory, 4096, 0, 0, 0, 0) == 0);
    long source = open_file("/tool", 0), output = open_file("/output/result.bin", 1);
    require(source >= 0 && output >= 0);
    for (;;) {
        long n = call6(0, source, (long)buffer, sizeof(buffer), 0, 0, 0);
        require(n >= 0);
        if (n == 0) break;
        require(call6(1, output, (long)buffer, n, 0, 0, 0) == n);
    }
    call6(3, source, 0, 0, 0, 0, 0); call6(3, output, 0, 0, 0, 0, 0);
    char *replacement[] = {"/output/result.bin", 0};
    require(call6(59, (long)replacement[0], (long)replacement, (long)env, 0, 0, 0) == -13);
    require(call6(322, -100, (long)"/tool", (long)replacement, (long)env, 0, 0) == -1);
    record(argc, argv);
    emit("CONTAINMENT_OK\n");
}

static void file_limit(void) {
    struct { usize handler, flags, restorer, mask; } ignore = {1, 0, 0, 0};
    require(call6(13, 25, (long)&ignore, 0, 8, 0, 0) == 0);
    long fd = open_file("/output/result.bin", 1);
    require(fd >= 0);
    long total = 0;
    for (;;) {
        long n = call6(1, fd, (long)buffer, sizeof(buffer), 0, 0, 0);
        if (n == -27) break;
        require(n > 0); total += n;
        require(total <= 1048576);
    }
    require(total == 1048576);
    emit("FILE_LIMIT_OK\n");
}

void entry(usize *stack) {
    long argc = stack[0];
    char **argv = (char **)(stack + 1);
    char **env = argv + argc + 1;
    require(argc >= 2);
    if (equal(argv[1], "record")) record(argc, argv);
    else if (equal(argv[1], "containment")) containment(argc, argv, env);
    else if (equal(argv[1], "memory")) {
        require(call6(9, 0, 268435456, 3, 0x22, -1, 0) == -12);
        emit("MEMORY_LIMIT_OK\n");
    } else if (equal(argv[1], "file")) file_limit();
    else if (equal(argv[1], "cpu")) { emit("CPU_STARTED\n"); for (;;) __asm__ volatile("" ::: "memory"); }
    else if (equal(argv[1], "wall")) {
        emit("WALL_STARTED\n");
        int wait_word = 0;
        call6(202, (long)&wait_word, 0, 0, 0, 0, 0);
        finish(92);
    } else if (equal(argv[1], "flood")) {
        for (usize i = 0; i < sizeof(buffer); i++) buffer[i] = 'x';
        for (;;) call6(1, 1, (long)buffer, sizeof(buffer), 0, 0, 0);
    } else finish(93);
    finish(0);
}

__asm__(".text\n.global _start\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall entry\n");
