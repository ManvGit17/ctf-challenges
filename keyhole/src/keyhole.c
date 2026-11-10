/*
 * keyhole - access terminal, v2.3
 *
 * Reads a "ticket" file produced by the gate service and an access code
 * typed on stdin. Prints GRANTED if the code matches the ticket, DENIED
 * otherwise. This source is for the challenge author's records only - the
 * binary players get is stripped and built with -O2 -s -static.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TICKET_MAGIC   "KHT1"
#define CODE_LEN       12
#define CHARSET        "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789"

typedef struct __attribute__((packed)) {
    char     magic[4];
    uint32_t seed;
    uint8_t  mode;
    uint8_t  reserved[3];
    uint8_t  target[CODE_LEN];
    uint8_t  noise[8];
} ticket_t; /* exactly 32 bytes */

/* ---- key schedule: 12 bytes derived from the ticket's seed ---- */
static void derive_keystream(uint32_t seed, uint8_t *k, int n) {
    uint32_t state = seed ^ 0xA53C9D1Fu;
    for (int i = 0; i < n; i++) {
        state = state * 0x41C64E6Du + 0x3039u;
        k[i] = (uint8_t)(state >> 24);
    }
}

static uint8_t rol8(uint8_t v, int n) { n &= 7; return (uint8_t)((v << n) | (v >> (8 - n))); }
static uint8_t ror8(uint8_t v, int n) { n &= 7; return (uint8_t)((v >> n) | (v << (8 - n))); }

/* ---- per-mode byte transforms, all invertible ---- */
static uint8_t mode_a(uint8_t c, uint8_t k, int i) {
    return rol8((uint8_t)(c ^ k), (i % 7) + 1);
}
static uint8_t mode_b(uint8_t c, uint8_t k, int i) {
    return (uint8_t)((uint8_t)(c + k) ^ (uint8_t)(i * 0x1d));
}
static uint8_t mode_c(uint8_t c, uint8_t k, const uint8_t *kall, int i) {
    return (uint8_t)(ror8(c, 3) ^ k ^ kall[(i + 5) % CODE_LEN]);
}

typedef uint8_t (*transform_fn)(uint8_t c, int i, const uint8_t *k);

static uint8_t t0(uint8_t c, int i, const uint8_t *k) { return mode_a(c, k[i], i); }
static uint8_t t1(uint8_t c, int i, const uint8_t *k) { return mode_b(c, k[i], i); }
static uint8_t t2(uint8_t c, int i, const uint8_t *k) { return mode_c(c, k[i], k, i); }

/* ---- decoy path: present in the binary, never reached by the real
 * check (mode is always 0/1/2). Exists to bait anyone who greps the
 * binary for flag-shaped strings or hooks the first "ACCEPT"-ish print
 * they find, instead of actually reversing the real comparison. ---- */
static const uint8_t LEGACY_BLOB[] = {
    0x3C, 0x36, 0x3B, 0x3D, 0x21, 0x14, 0x6B, 0x19, 0x1F, 0x05, 0x0E, 0x08,
    0x03, 0x05, 0x11, 0x1F, 0x1F, 0x0A, 0x05, 0x08, 0x1F, 0x0C, 0x1F, 0x08,
    0x09, 0x13, 0x14, 0x1D, 0x27
};

static void decode_legacy_string(void) {
    uint8_t key = 0x5A;
    char buf[sizeof(LEGACY_BLOB) + 1];
    size_t n = sizeof(LEGACY_BLOB);
    for (size_t i = 0; i < n; i++) buf[i] = (char)(LEGACY_BLOB[i] ^ key);
    buf[n] = '\0';
    fprintf(stderr, "[legacy] %s\n", buf);
}

static uint8_t legacy_transform(uint8_t c, int i, const uint8_t *k) {
    (void)i; (void)k;
    decode_legacy_string();
    return c;
}

static const transform_fn TABLE[4] = { t0, t1, t2, legacy_transform };

static void usage(const char *argv0) {
    fprintf(stderr, "keyhole v2.3 - access terminal\n");
    fprintf(stderr, "usage: %s <ticket.bin>\n", argv0);
    fprintf(stderr, "hint: set KEYHOLE_DEBUG=1 for verbose diagnostics\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open ticket: %s\n", argv[1]);
        return 1;
    }
    ticket_t ticket;
    size_t n = fread(&ticket, 1, sizeof(ticket), f);
    fclose(f);
    if (n != sizeof(ticket) || memcmp(ticket.magic, TICKET_MAGIC, 4) != 0) {
        printf("bad ticket\n");
        return 1;
    }

    if (getenv("KEYHOLE_DEBUG")) {
        fprintf(stderr, "[debug] ticket loaded, magic ok\n");
    }

    /* undocumented path: present mostly to give strings(1) something to
     * find ("--legacy") that leads nowhere useful against the real gate */
    if (argc >= 3 && strcmp(argv[2], "--legacy") == 0) {
        uint8_t k[CODE_LEN];
        derive_keystream(ticket.seed, k, CODE_LEN);
        TABLE[3](0, 0, k);
        printf("DENIED\n");
        return 1;
    }

    int mode = ticket.mode % 3;
    uint8_t k[CODE_LEN];
    derive_keystream(ticket.seed, k, CODE_LEN);

    char code[CODE_LEN + 2];
    printf("Access code: ");
    fflush(stdout);
    if (!fgets(code, sizeof(code), stdin)) {
        printf("DENIED\n");
        return 1;
    }
    size_t len = strlen(code);
    while (len > 0 && (code[len - 1] == '\n' || code[len - 1] == '\r')) {
        code[--len] = '\0';
    }
    if (len != CODE_LEN) {
        printf("DENIED\n");
        return 1;
    }
    for (size_t i = 0; i < len; i++) {
        if (!strchr(CHARSET, code[i])) {
            printf("DENIED\n");
            return 1;
        }
    }

    uint8_t computed[CODE_LEN];
    for (int i = 0; i < CODE_LEN; i++) {
        computed[i] = TABLE[mode]((uint8_t)code[i], i, k);
    }

    if (memcmp(computed, ticket.target, CODE_LEN) == 0) {
        printf("GRANTED\n");
    } else {
        printf("DENIED\n");
    }
    return 0;
}
