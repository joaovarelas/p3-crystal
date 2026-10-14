#pragma once
#include "native.h"

typedef struct
{
    int length;
    char value[];
} RESOURCE;

#define GETRESOURCE(x) ((RESOURCE *)((char *)&(x)))

/* Unmasks src XOR key into dst.
 * dst must be at least src->length bytes.
 * Returns number of bytes written. */
int resource_unmask(const RESOURCE *src, const RESOURCE *key, u8 *dst);
