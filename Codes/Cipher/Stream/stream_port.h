/*
    Stream cipher port (linker contract for main.c)
    Archive of Reversing.ID

    Each algorithm code.c implements these symbols when built with main.c.
    Link exactly one cipher object file per build.

    Per-build sizes (STREAM_*_BYTES) tell how many bytes each cipher reads
    from the harness buffers. Semantics are documented above stream_encrypt()
    in that cipher's code.c.
*/
#ifndef STREAM_PORT_H
#define STREAM_PORT_H

#include <stdint.h>
#include <stddef.h>

extern const uint32_t STREAM_KEY_BYTES;
extern const uint32_t STREAM_NONCE_BYTES;
extern const uint32_t STREAM_COUNTER_BYTES;

void stream_encrypt(
    uint8_t *data,
    size_t  length,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *counter
);

void stream_decrypt(
    uint8_t *data,
    size_t  length,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *counter
);

#endif
