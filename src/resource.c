#include "resource.h"

int resource_unmask(const RESOURCE *src, const RESOURCE *key, u8 *dst)
{
    int i;
    for (i = 0; i < src->length; i++)
        dst[i] = (u8)(src->value[i] ^ key->value[i % key->length]);
    return src->length;
}


