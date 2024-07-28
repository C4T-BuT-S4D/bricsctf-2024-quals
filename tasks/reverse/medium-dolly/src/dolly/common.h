#ifndef _COMMON_H
#define _COMMON_H

#include <stdlib.h>

/*
static void DecryptData(unsigned char *data, size_t length) {
    unsigned char tmp = 0xFF;

    for (size_t i = 0; i < length; i += 1) {
        unsigned char value = data[i];

        value = (value ^ tmp) & 0xFF;

        value = (value ^ (i)) & 0xFF;
        value = (value + (i*i)) & 0xFF;
        value = (value ^ (i*i*i)) & 0xFF;
        value = (value + (i*i*i*i)) & 0xFF;

        data[i] = value;

        tmp = (tmp + value) & 0xFF;
    }

    return;
}
*/

static void DecryptData(unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i += 1) {
        data[i] = data[i] ^ 0xAA;
    }

    return;
}

#endif /* _COMMON_H */
