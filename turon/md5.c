#include "turon/turon.h"
#include "turon/turon_md5.h"
#include <stdio.h>
/*#include <string.h>
#include <stdlib.h>*/

const char empty_md5_buffer[56] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const char empty_md5_string[32] = "                                ";

int process_512_bit_md5_chunk (turon_md5_t *md5) {

    int i;
    uint32_t a, b, c, d, j, k, l, temp;

    a = md5->word_a;
    b = md5->word_b;
    c = md5->word_c;
    d = md5->word_d;

    for(i = 0; i<64; i++) {

        if (i < 16) {
            j = (b & c) | ((~b) & d);
            k = i;
        } else if (i < 32) {
            j = (d & b) | ((~d) & c);
            k = (5*i + 1) % 16;
        } else if (i < 48) {
            j = b ^ c ^ d;
            k = (3*i + 5) % 16;          
        } else {
            j = c ^ (b | (~d));
            k = (7*i) % 16;
        }
        temp = d;
        d = c;
        c = b;
        /* Calculate 32-bit value in a way which works on both big and
           little endian systems */
        l = ((uint8_t)md5->buffer[(k*4)+0]) +
            ((uint8_t)md5->buffer[(k*4)+1] << 8) +
            ((uint8_t)md5->buffer[(k*4)+2] << 16) +
            ((uint8_t)md5->buffer[(k*4)+3] << 24);
        b = b + TURON_MD5_ROTATE((a + j + turon_md5_rotate_array[i] + l), turon_md5_shift_array[i]);
        a = temp;
    }

    md5->word_a += a;
    md5->word_b += b;
    md5->word_c += c;
    md5->word_d += d;
 
    return TURON_OK;
}

int turon_md5_init (turon_md5_t *md5, void **data) {
    md5->data = data;
    md5->word_a = TURON_MD5_WORDA_START;
    md5->word_b = TURON_MD5_WORDB_START;
    md5->word_c = TURON_MD5_WORDC_START;
    md5->word_d = TURON_MD5_WORDD_START;
    md5->length = 0;
    md5->buffer_index = 0;

    memcpy (&md5->hash_string, &empty_md5_string, 32);
    md5->hash_string[32] = "\0";

    return TURON_OK;
}

int turon_md5_feed (turon_md5_t *md5, char *buf, int buf_len) {

    int passed_buf_index, copy_len;

    passed_buf_index = 0;

    /* 64 bytes == 512 bits. Process 64 bytes at a time, but only
       when I have a full 64 byte buffer. */
    while (md5->buffer_index + (buf_len - passed_buf_index) >= 64) {
        copy_len = 64 - md5->buffer_index;
        memcpy (&md5->buffer[md5->buffer_index], &buf[passed_buf_index], copy_len);
        passed_buf_index += copy_len;
        process_512_bit_md5_chunk (md5);
        md5->buffer_index = 0;
    }
    if (buf_len > passed_buf_index) {
        copy_len = buf_len - passed_buf_index;
        memcpy (&md5->buffer[md5->buffer_index], &buf[passed_buf_index], copy_len);
        md5->buffer_index += copy_len;
    } 

    md5->length += buf_len*8;

    return TURON_OK;
}

int turon_md5_finalize (turon_md5_t *md5) {

    if (md5->buffer_index < 56) {
        md5->buffer[md5->buffer_index] = 128;
        memcpy (&md5->buffer[md5->buffer_index+1], &empty_md5_buffer, 56 - md5->buffer_index - 1);
    } else {
        md5->buffer[md5->buffer_index] = 128;
        memcpy (&md5->buffer[(md5->buffer_index)+1], &empty_md5_buffer, 64 - md5->buffer_index - 1);
        process_512_bit_md5_chunk (md5);
        md5->buffer_index = 0;
        memcpy (&md5->buffer[md5->buffer_index], &empty_md5_buffer, 56);
    }
    md5->buffer[56] = md5->length & 0x00000000000000ff;
    md5->buffer[57] = (md5->length & 0x000000000000ff00) >> 8;
    md5->buffer[58] = (md5->length & 0x0000000000ff0000) >> 16;
    md5->buffer[59] = (md5->length & 0x00000000ff000000) >> 24;
    md5->buffer[60] = (md5->length & 0x000000ff00000000) >> 32;
    md5->buffer[61] = (md5->length & 0x0000ff0000000000) >> 40;
    md5->buffer[62] = (md5->length & 0x00ff000000000000) >> 48;
    md5->buffer[63] = md5->length >> 56;
    process_512_bit_md5_chunk (md5);
    md5->buffer_index = 0;

    sprintf(md5->hash_string, "%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x\0",
            md5->word_a & 0x000000ff,
            (md5->word_a & 0x0000ff00) >> 8,
            (md5->word_a & 0x00ff0000) >> 16,
            md5->word_a >> 24,
            md5->word_b & 0x000000ff,
            (md5->word_b & 0x0000ff00) >> 8,
            (md5->word_b & 0x00ff0000) >> 16,
            md5->word_b >> 24,
            md5->word_c & 0x000000ff,
            (md5->word_c & 0x0000ff00) >> 8,
            (md5->word_c & 0x00ff0000) >> 16,
            md5->word_c >> 24,
            md5->word_d & 0x000000ff,
            (md5->word_d & 0x0000ff00) >> 8,
            (md5->word_d & 0x00ff0000) >> 16,
            md5->word_d >> 24
        );

    return TURON_OK;
}

