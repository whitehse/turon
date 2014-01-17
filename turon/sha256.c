#include "turon/turon.h"
#include "turon/turon_sha256.h"
#include <stdio.h>
/*#include <string.h>
#include <stdlib.h>*/

const char empty_sha256_buffer[56] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const char empty_sha256_string[64] = "                                                                ";

int process_512_bit_sha256_chunk (turon_sha256_t *sha256) {

    int i;
    uint32_t a, b, c, d, e, f, g, h, j, k, ch, maj, temp1, temp2;
    uint32_t w[64];

    for(i = 0; i<63; i++) {
        w[i] = 0;
    }

    for(i = 0; i<16; i++) {
        /* Calculate 32-bit value in a way which works on both big and
           little endian systems */
        w[i] = ((uint8_t)sha256->buffer[(i*4)+0] << 24) |
            ((uint8_t)sha256->buffer[(i*4)+1] << 16) |
            ((uint8_t)sha256->buffer[(i*4)+2] << 8) |
            ((uint8_t)sha256->buffer[(i*4)+3] );
    }

#define SHIFT(x,n) ((x & 0xFFFFFFFF) >> n)
#define ROTATE(x,n) (SHIFT(x,n) | (x << (32 - n)))

    for(i = 16; i<64; i++) {
        j = ROTATE(w[i-15], 7) ^ ROTATE(w[i-15], 18) ^ SHIFT(w[i-15], 3);
        k = ROTATE(w[i-2], 17) ^ ROTATE(w[i-2], 19) ^ SHIFT(w[i-2], 10);
        w[i] = w[i-16] + j + w[i-7] + k;
    }

    a = sha256->word_a;
    b = sha256->word_b;
    c = sha256->word_c;
    d = sha256->word_d;
    e = sha256->word_e;
    f = sha256->word_f;
    g = sha256->word_g;
    h = sha256->word_h;

    for(i = 0; i<64; i++) {

        k = ROTATE(e, 6) ^ ROTATE(e, 11) ^ ROTATE(e, 25);
        ch = (e & f) ^ ((~e) & g);
        temp1 = h + k + ch + turon_sha256_rotate_array[i] + w[i];
        j = ROTATE(a, 2) ^ ROTATE(a, 13) ^ ROTATE(a, 22);
        maj = (a & b) ^ (a & c) ^ (b & c);
        temp2 = j + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    sha256->word_a += a;
    sha256->word_b += b;
    sha256->word_c += c;
    sha256->word_d += d;
    sha256->word_e += e;
    sha256->word_f += f;
    sha256->word_g += g;
    sha256->word_h += h;
 
    return TURON_OK;
}

int turon_sha256_init (turon_sha256_t *sha256, void **data) {
    sha256->data = data;
    sha256->word_a = TURON_SHA256_WORDA_START;
    sha256->word_b = TURON_SHA256_WORDB_START;
    sha256->word_c = TURON_SHA256_WORDC_START;
    sha256->word_d = TURON_SHA256_WORDD_START;
    sha256->word_e = TURON_SHA256_WORDE_START;
    sha256->word_f = TURON_SHA256_WORDF_START;
    sha256->word_g = TURON_SHA256_WORDG_START;
    sha256->word_h = TURON_SHA256_WORDH_START;
    sha256->length = 0;
    sha256->buffer_index = 0;

    memcpy (&sha256->hash_string, &empty_sha256_string, 64);
    sha256->hash_string[64] = "\0";

    return TURON_OK;
}

int turon_sha256_feed (turon_sha256_t *sha256, char *buf, int buf_len) {

    int passed_buf_index, copy_len;

    passed_buf_index = 0;

    /* 64 bytes == 512 bits. Process 64 bytes at a time, but only
       when I have a full 64 byte buffer. */
    while (sha256->buffer_index + (buf_len - passed_buf_index) >= 64) {
        copy_len = 64 - sha256->buffer_index;
        memcpy (&sha256->buffer[sha256->buffer_index], &buf[passed_buf_index], copy_len);
        passed_buf_index += copy_len;
        process_512_bit_sha256_chunk (sha256);
        sha256->buffer_index = 0;
    }
    if (buf_len > passed_buf_index) {
        copy_len = buf_len - passed_buf_index;
        memcpy (&sha256->buffer[sha256->buffer_index], &buf[passed_buf_index], copy_len);
        sha256->buffer_index += copy_len;
    } 

    sha256->length += buf_len*8;

    return TURON_OK;
}

int turon_sha256_finalize (turon_sha256_t *sha256) {

    if (sha256->buffer_index < 56) {
        sha256->buffer[sha256->buffer_index] = 128;
        memcpy (&sha256->buffer[sha256->buffer_index+1], &empty_sha256_buffer, 56 - sha256->buffer_index - 1);
    } else {
        sha256->buffer[sha256->buffer_index] = 128;
        memcpy (&sha256->buffer[(sha256->buffer_index)+1], &empty_sha256_buffer, 64 - sha256->buffer_index - 1);
        process_512_bit_sha256_chunk (sha256);
        sha256->buffer_index = 0;
        memcpy (&sha256->buffer[sha256->buffer_index], &empty_sha256_buffer, 56);
    }

    sha256->buffer[63] = sha256->length & 0x00000000000000ff;
    sha256->buffer[62] = (sha256->length & 0x000000000000ff00) >> 8;
    sha256->buffer[61] = (sha256->length & 0x0000000000ff0000) >> 16;
    sha256->buffer[60] = (sha256->length & 0x00000000ff000000) >> 24;
    sha256->buffer[59] = (sha256->length & 0x000000ff00000000) >> 32;
    sha256->buffer[58] = (sha256->length & 0x0000ff0000000000) >> 40;
    sha256->buffer[57] = (sha256->length & 0x00ff000000000000) >> 48;
    sha256->buffer[56] = sha256->length >> 56;
    process_512_bit_sha256_chunk (sha256);
    sha256->buffer_index = 0;

    sprintf(sha256->hash_string, "%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x\0",
            sha256->word_a >> 24,
            (sha256->word_a & 0x00ff0000) >> 16,
            (sha256->word_a & 0x0000ff00) >> 8,
            sha256->word_a & 0x000000ff,
            sha256->word_b >> 24,
            (sha256->word_b & 0x00ff0000) >> 16,
            (sha256->word_b & 0x0000ff00) >> 8,
            sha256->word_b & 0x000000ff,
            sha256->word_c >> 24,
            (sha256->word_c & 0x00ff0000) >> 16,
            (sha256->word_c & 0x0000ff00) >> 8,
            sha256->word_c & 0x000000ff,
            sha256->word_d >> 24,
            (sha256->word_d & 0x00ff0000) >> 16,
            (sha256->word_d & 0x0000ff00) >> 8,
            sha256->word_d & 0x000000ff,
            sha256->word_e >> 24,
            (sha256->word_e & 0x00ff0000) >> 16,
            (sha256->word_e & 0x0000ff00) >> 8,
            sha256->word_e & 0x000000ff,
            sha256->word_f >> 24,
            (sha256->word_f & 0x00ff0000) >> 16,
            (sha256->word_f & 0x0000ff00) >> 8,
            sha256->word_f & 0x000000ff,
            sha256->word_g >> 24,
            (sha256->word_g & 0x00ff0000) >> 16,
            (sha256->word_g & 0x0000ff00) >> 8,
            sha256->word_g & 0x000000ff,
            sha256->word_h >> 24,
            (sha256->word_h & 0x00ff0000) >> 16,
            (sha256->word_h & 0x0000ff00) >> 8,
            sha256->word_h & 0x000000ff
        );

    return TURON_OK;
}

