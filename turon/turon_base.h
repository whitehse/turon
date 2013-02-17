
/*
 * Copyright (C) 2013 Dan White
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef TURON_BASE_H
#define TURON_BASE_H

/* Return types */
#define TURON_OK          0   /* successful result */
#define TURON_FAIL       -1   /* generic failure */
#define TURON_NOMEM      -2   /* memory shortage failure */
#define TURON_BUFOVER    -3   /* overflowed buffer */
#define TURON_BADPARAM   -4   /* invalid parameter supplied */
#define TURON_NOTINIT    -5   /* TURON library not initialized */

typedef struct turon_md5 {
    uint32_t word_a;
    uint32_t word_b;
    uint32_t word_c;
    uint32_t word_d;
    uint64_t length;
    char buffer[64];
    int buffer_index;
    char hash_string[33];
    void **data; 
} turon_md5_t;

const uint32_t turon_md5_rotate_array[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

const uint32_t turon_md5_shift_array[] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

#define TURON_MD5_ROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

#define TURON_MD5_WORDA_START 0x67452301
#define TURON_MD5_WORDB_START 0xefcdab89
#define TURON_MD5_WORDC_START 0x98badcfe
#define TURON_MD5_WORDD_START 0x10325476

int turon_md5_init (turon_md5_t *, void **);
int turon_md5_feed (turon_md5_t *, char *, int);
int turon_md5_finalize (turon_md5_t *);

#endif // TURON_BASE_H
