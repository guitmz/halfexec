# halfexec

halfexec is a small userland ELF loader for Linux x64, written in FASM. It runs another program without asking the kernel to `execve` it. It reads the target file, maps it into memory by itself, builds a fresh stack and jumps to the entry point.

This is the companion code for the tmp.0ut article at https://tmpout.sh/5/13.html

## What it can run

* Static binaries, both classic and PIE
* Dynamic binaries that use an interpreter like `ld.so`
* Binaries built without libc, in C or plain assembly
* Real world tools such as busybox

Fixed address (ET_EXEC) programs are started in a forked child. A tiny trampoline is copied to scratch memory first so the loader does not overwrite itself while mapping the target. The parent waits and returns the child's exit code.

## Limits

* Target files must be 1 MB or smaller
* Only RELATIVE and IRELATIVE relocations are handled for PIE files without an interpreter
* Linux x64 only

## Build

You need `fasm`, and `gcc` for the test programs.

```sh
make
```

## Usage

```sh
./halfexec /path/to/program [args...]
```

The target receives its own path as `argv[0]`, followed by any extra arguments.

Set `HALFEXEC_DEBUG=1` to print what the loader is doing.

```sh
HALFEXEC_DEBUG=1 ./halfexec /bin/true
```

## Tests

```sh
make run
```

This builds sample programs into `/tmp` and runs each one through halfexec, checking the exit code. Pass `DEBUG=1` to see loader output. Use `make inspect` to view the ELF type of each sample and `make clean` to remove everything.

## Layout

* `halfexec.asm` is the main loader
* `utils.inc` holds syscall numbers, constants and structures
* `runtime/` holds the loader stages for validation, relocation, interpreter loading, stack setup, the trampoline and data
* `tests/` holds the sample programs
