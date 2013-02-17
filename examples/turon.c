#include "turon/turon.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main (int argc, char **argv) {
	turon_md5_t *md5 = (struct turon_md5_t*)malloc(sizeof(struct turon_md5));
	int r = turon_md5_init(md5, NULL);

    r = turon_md5_feed (md5, "The quick brown fox jumps over the lazy dog", 43);
    r = turon_md5_finalize (md5);

    printf ("%s\n", md5->hash_string);
}
