#include "turon/turon.h"
/*#include <string.h>
#include <stdio.h>
#include <stdlib.h>*/

int turon_md5_init (turon_md5_t *md5, void **data) {
    md5->data = data;
    return TURON_OK;
}
