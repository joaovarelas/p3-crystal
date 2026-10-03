#include "utils.h"


void bytes_to_wchar(const uint8_t* src, size_t len, wchar_t* dest) {
    size_t i;
    for (i = 0; i < len; i += 2) {
        if (i + 1 < len) {
            dest[i / 2] = (wchar_t)(src[i] | (src[i + 1] << 8));
        } else {
            dest[i / 2] = (wchar_t)src[i];
        }
    }
    dest[len / 2] = L'\0'; 
}

