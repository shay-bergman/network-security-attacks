/*
 * payload.h
 *
 * Construction of the stack-overflow exploit payload: NOP padding, the
 * overwritten return address, position-independent shellcode, and the argv
 * data the shellcode references.
 */

#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Parse a decimal or 0x-hex unsigned 64-bit integer. Returns false on error. */
bool parse_u64(const char *s, uint64_t *out);

/*
 * Build the exploit payload for a buffer at runtime address buffer_addr whose
 * saved return address sits ret_offset bytes into it. On success returns a
 * malloc'ed buffer (caller frees) and stores its length in *out_size; returns
 * NULL on error.
 */
uint8_t *build_payload(uint64_t buffer_addr, uint64_t ret_offset, size_t *out_size);

#endif /* PAYLOAD_H */
