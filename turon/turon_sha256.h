
/*
 * Copyright (C) 2014 Dan White
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

#ifndef TURON_SHA256_H
#define TURON_SHA256_H

#include <stdint.h>

typedef struct turon_sha256 {
    uint32_t word_a;
    uint32_t word_b;
    uint32_t word_c;
    uint32_t word_d;
    uint32_t word_e;
    uint32_t word_f;
    uint32_t word_g;
    uint32_t word_h;
    uint64_t length;
    char buffer[64];
    int buffer_index;
    char hash_string[65];
    void **data; 
} turon_sha256_t;

const uint32_t turon_sha256_rotate_array[64] = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
   0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
   0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
   0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
   0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
   0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
   0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
   0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
   0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define TURON_SHA256_WORDA_START 0x6a09e667
#define TURON_SHA256_WORDB_START 0xbb67ae85
#define TURON_SHA256_WORDC_START 0x3c6ef372
#define TURON_SHA256_WORDD_START 0xa54ff53a
#define TURON_SHA256_WORDE_START 0x510e527f
#define TURON_SHA256_WORDF_START 0x9b05688c
#define TURON_SHA256_WORDG_START 0x1f83d9ab
#define TURON_SHA256_WORDH_START 0x5be0cd19

int turon_sha256_init (turon_sha256_t *, void **);
int turon_sha256_feed (turon_sha256_t *, char *, int);
int turon_sha256_finalize (turon_sha256_t *);

#endif // TURON_SHA256_H
