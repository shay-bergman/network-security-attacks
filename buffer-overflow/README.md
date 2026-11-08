# Stack Buffer Overflow

*Remote stack-smashing exploit with position-independent shellcode.*

## Overview

A network service copies attacker-supplied input into a fixed-size stack buffer
without bounds checking. This tool builds a payload that overflows the buffer,
overwrites the saved return address, and redirects execution into shellcode
carried by the payload, which runs a chosen program on the target.

## How it works

On x86-64 the saved return address sits above local buffers on the stack. An
oversized write past the end of a buffer overwrites it, so when the vulnerable
function returns the CPU jumps wherever that slot now points.

The exploit is built for a small overflow offset, where there is little room
before the return address. It places everything *after* the saved return
address and points the overwritten address forward:

```
[ NOP padding ][ saved RIP ][ shellcode ][ argv[] ][ strings ]
                    |            ^
                    +------------+   overwritten to point forward
```

Absolute addresses inside the shellcode (the program path and the `argv` array)
are computed at runtime from a leaked stack address, so the exploit does not
rely on fixed addresses. The shellcode is a minimal `execve` of a fixed program
path, passing a neutral proof-of-exploitation marker as `argv[1]`. In the
original lab a unique identifier was used there to attribute a successful run;
it has no functional role and is a placeholder constant.

Source layout:

- `payload.c` / `payload.h` — argument parsing and payload/shellcode construction.
- `overflow_exploit.c` — delivery driver (connect, send, teardown).

## Building

```sh
make
```

## Usage

```sh
./overflow_exploit <leaked_stack_addr> <ret_offset>
```

- `leaked_stack_addr` — runtime start address of the vulnerable buffer, obtained
  from an information leak against the target.
- `ret_offset` — distance in bytes from that buffer to the saved return address.

Both arguments accept decimal or `0x`-prefixed hexadecimal.

## Lab/target assumptions

- A reachable vulnerable TCP service on the lab host (`192.168.1.202:12345`).
- An x86-64 Linux target with an executable stack and a usable address leak,
  matching the sandboxed lab configuration this was written against.

## License

MIT. See the [LICENSE](../LICENSE) at the repository root.
