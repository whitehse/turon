#include "turon/turon.h"
/*#include <string.h>
#include <stdlib.h>*/

char empty_buffer[56] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

int process_512_bit_chunk (md5) {
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

    int i;
    for (i=0; i<32; i++) {
        md5->hash_string[i] = " ";
    }
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
        process_512_bit_chunk (md5);
        md5->buffer_index = 0;
    }
    if (buf_len > passed_buf_index) {
        copy_len = buf_len - passed_buf_index;
        memcpy (&md5->buffer[md5->buffer_index], &buf[passed_buf_index], copy_len);
    } 

    md5->length += buf_len*8;

    return TURON_OK;
}

int turon_md5_finalize (turon_md5_t *md5) {

    if (md5->buffer_index < 56) {
        md5->buffer[md5->buffer_index] = 128;
        memcpy (&md5->buffer[md5->buffer_index+1], &empty_buffer, 56 - md5->buffer_index - 1);
    } else {
        md5->buffer[md5->buffer_index] = 128;
        memcpy (&md5->buffer[(md5->buffer_index)+1], &empty_buffer, 64 - md5->buffer_index - 1);
        process_512_bit_chunk (md5);
        md5->buffer_index = 0;
        memcpy (&md5->buffer[md5->buffer_index], &empty_buffer, 56);
    }
    /* TODO: I need to guarantee this is in bigendian format, per RFC 1321 */
    memcpy(&md5->buffer[56], &(md5->length), 4);
    process_512_bit_chunk (md5);
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

