#pragma once

#include <windows.h>
#include <stdint.h>
#include <stdarg.h>

#include "dfr.h"

#define GETRESOURCE(x) ( char * ) &x
#define memset(x, y, z) __stosb ( ( unsigned char * ) x, y, z );

typedef struct {
    int  length;
    char value [ ];
} RESOURCE;


void bytes_to_wchar(const uint8_t* src, size_t len, wchar_t* dest);

