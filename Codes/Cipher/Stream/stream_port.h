/*
    Stream cipher port (linker contract for main.c)
    Archive of Reversing.ID

    Each algorithm code.c implements these symbols when built with main.c.
    Link exactly one cipher object file per build.
*/
#ifndef STREAM_PORT_H
#define STREAM_PORT_H

#include <stdint.h>
#include <stddef.h>

extern const uint32_t STREAM_KEY_BYTES;
extern const uint32_t STREAM_NONCE_BYTES;

void stream_encrypt(uint8_t *data, size_t length, const uint8_t *key, const uint8_t *nonce);
void stream_decrypt(uint8_t *data, size_t length, const uint8_t *key, const uint8_t *nonce);

#endif
