#include "turon/turon.h"
#include "turon/turon_md5.h"
#include "turon/turon_sha256.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main (int argc, char **argv) {
    turon_md5_t *md5 = (struct turon_md5_t*)malloc(sizeof(struct turon_md5));
    int r = turon_md5_init(md5, NULL);

    r = turon_md5_feed (md5, "The quick brown fox jumps over the lazy dog", 43);
    r = turon_md5_finalize (md5);

    printf ("md5sum: %s\n", md5->hash_string);

    free (md5);

    turon_sha256_t *sha256 = (struct turon_sha256_t*)malloc(sizeof(struct turon_sha256));
    r = turon_sha256_init(sha256, NULL);

    r = turon_sha256_feed (sha256, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
    r = turon_sha256_finalize (sha256);

    printf ("sha256sum: %s\n", sha256->hash_string);

    free (sha256);
}
