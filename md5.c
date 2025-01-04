#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

static size_t pad(const uint8_t *message, size_t size, uint8_t **padded);
static uint32_t rotl(const uint32_t value, int shift);
static void to_bytes_reversed(uint32_t value, uint8_t *bytes);

static const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

// specifies the per-round shift amounts
static const uint32_t s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

int md5_hash(const uint8_t *message, size_t size, uint8_t *out) {
    uint8_t *padded;
    if (pad(message, size, &padded))
        return -1;

    // initial state
    uint32_t a0 = 0x67452301;
    uint32_t b0 = 0xefcdab89;
    uint32_t c0 = 0x98badcfe;
    uint32_t d0 = 0x10325476;

    size_t nchunks = size / 56 + 1;
    for (int chunk = 0; chunk < nchunks; chunk++) {
        uint32_t a = a0;
        uint32_t b = b0;
        uint32_t c = c0;
        uint32_t d = d0;

        for (int i = 0; i < 64; i++) {
            uint32_t f, g;

            if (i < 16) {
                f = (b & c) | (~b & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | (~d & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else if (i < 64) {
                f = c ^ (b | ~d);
                g = (7 * i) % 16;
            }

            uint32_t m = *((uint32_t *)(padded + (chunk * 64)) + g);

            f += a + K[i] + m;
            a = d;
            d = c;
            c = b;
            b += rotl(f, s[i]);
        }

        a0 += a;
        b0 += b;
        c0 += c;
        d0 += d;
    }

    to_bytes_reversed(a0, out);
    to_bytes_reversed(b0, out + 4);
    to_bytes_reversed(c0, out + 8);
    to_bytes_reversed(d0, out + 12);

    free(padded);

    return 0;
}

void to_hexdigest(const uint8_t *digest, char *hexdigest) {
    for (int i = 0; i < 16; i++)
        snprintf(hexdigest + (i * 2), (16 * 2) + 1, "%02x", digest[i]);
}

static size_t pad(const uint8_t *message, size_t size, uint8_t **padded) {
    if (size % 64 == 56)
        return size;

    *padded = malloc((size / 64 + 1) * 64);
    if (!padded)
        return -1;
    memcpy(*padded, message, size);

    size_t new_size = size;
    (*padded)[new_size++] = 0x80;
    while (new_size % 64 != 56) (*padded)[new_size++] = 0;

    // add length of the original message in bits to the end of the padded
    // message
    uint64_t *length = (uint64_t *)(*padded + new_size);
    *length = size * 8;

    return 0;
}

// taken from
// https://stackoverflow.com/questions/10134805/bitwise-rotate-left-function
static uint32_t rotl(uint32_t value, int shift) {
    if ((shift &= sizeof(value) * 8 - 1) == 0)
        return value;
    return (value << shift) | (value >> (sizeof(value) * 8 - shift));
}

static void to_bytes_reversed(uint32_t value, uint8_t *bytes) {
    bytes[0] = value & 0xFF;
    bytes[1] = (value >> 8) & 0xFF;
    bytes[2] = (value >> 16) & 0xFF;
    bytes[3] = (value >> 24) & 0xFF;
}
