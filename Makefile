CC := gcc
FASM := fasm
LOADER := halfexec
DEBUG ?=
DEBUG_ENV := $(if $(DEBUG),HALFEXEC_DEBUG=$(DEBUG) ,)

# Sample outputs in /tmp
LIBC_EXEC_STATIC := /tmp/exec_static_libc
LIBC_EXEC_DYN := /tmp/exec_dyn_libc
LIBC_PIE_DYN := /tmp/pie_dyn_libc
LIBC_PIE_STATIC := /tmp/pie_static_libc
NOLIBC_EXEC_C := /tmp/nolibc_exec_c
NOLIBC_PIE_C := /tmp/nolibc_pie_c
NOLIBC_EXEC_ASM := /tmp/exec_asm
ARGV_EXEC_C := /tmp/argv_exec_c
ARGV_PIE_C := /tmp/argv_pie_c

COMMON_CFLAGS := -Wall -Wextra
NOLIBC_CFLAGS := -nostdlib -fno-stack-protector -Wl,--build-id=none

.PHONY: all clean inspect inspect-all binaries run trace

define run_expect
	@$(DEBUG_ENV)./$(LOADER) $(1); \
	status=$$?; \
	if [ $$status -ne $(2) ]; then \
		echo "FAIL: ./$(LOADER) $(1) exited $$status, expected $(2)"; \
		exit $$status; \
	fi
endef

all: $(LOADER)

$(LOADER): \
	halfexec.asm \
	utils.inc \
	runtime/validate.inc \
	runtime/reloc.inc \
	runtime/interp.inc \
	runtime/stack.inc \
	runtime/rwdata.inc \
	runtime/rodata.inc \
	runtime/trampoline.inc
	$(FASM) halfexec.asm
	chmod +x $(LOADER)

$(LIBC_EXEC_STATIC): tests/exec_static.c
	$(CC) $(COMMON_CFLAGS) -static -no-pie -o $@ $<

$(LIBC_EXEC_DYN): tests/exec_static.c
	$(CC) $(COMMON_CFLAGS) -no-pie -o $@ $<

$(LIBC_PIE_DYN): tests/exec_static.c
	$(CC) $(COMMON_CFLAGS) -o $@ $<

$(LIBC_PIE_STATIC): tests/exec_static.c
	$(CC) $(COMMON_CFLAGS) -static-pie -o $@ $<

$(NOLIBC_EXEC_C): tests/nolib.c
	$(CC) $(NOLIBC_CFLAGS) -static -no-pie -o $@ $<

$(NOLIBC_PIE_C): tests/nolib.c
	$(CC) $(NOLIBC_CFLAGS) -static-pie -o $@ $<

$(NOLIBC_EXEC_ASM): tests/exec_asm.asm
	$(FASM) $< $@
	chmod +x $@

# The argv binary is built twice so the exact same argument/stack checks 
# do both ET_EXEC and ET_DYN startup paths
$(ARGV_EXEC_C): tests/argv_nolib.c
	$(CC) $(NOLIBC_CFLAGS) -static -no-pie -DEXPECTED_SELF=\"$(ARGV_EXEC_C)\" -o $@ $<

$(ARGV_PIE_C): tests/argv_nolib.c
	$(CC) $(NOLIBC_CFLAGS) -static-pie -DEXPECTED_SELF=\"$(ARGV_PIE_C)\" -o $@ $<

SAMPLES := $(LIBC_EXEC_STATIC) $(LIBC_EXEC_DYN) $(LIBC_PIE_DYN) $(LIBC_PIE_STATIC) \
	$(NOLIBC_EXEC_C) $(NOLIBC_PIE_C) $(NOLIBC_EXEC_ASM) $(ARGV_EXEC_C) $(ARGV_PIE_C)

binaries: $(SAMPLES)

inspect: binaries
	for f in $(SAMPLES); do \
		echo "== $$f =="; \
		file "$$f"; \
		readelf -h "$$f" | grep "Type:"; \
		readelf -l "$$f" | grep INTERP || true; \
		echo; \
	done

# A "richer" inspection target is handy when comparing the exact ELF shape that
# triggered a loader issue
inspect-all: binaries
	for f in $(SAMPLES); do \
		echo "== $$f =="; \
		file "$$f"; \
		readelf -h "$$f"; \
		readelf -l "$$f"; \
		readelf -d "$$f" 2>/dev/null || true; \
		echo; \
	done

run: $(LOADER) binaries
	$(call run_expect,$(NOLIBC_EXEC_C),0)
	$(call run_expect,$(NOLIBC_PIE_C),0)
	$(call run_expect,$(NOLIBC_EXEC_ASM),0)
	$(call run_expect,$(ARGV_EXEC_C) alpha beta,0)
	$(call run_expect,$(ARGV_PIE_C) alpha beta,0)
	$(call run_expect,$(LIBC_EXEC_STATIC),13)
	$(call run_expect,$(LIBC_EXEC_DYN),13)
	$(call run_expect,$(LIBC_PIE_DYN),13)
	$(call run_expect,$(LIBC_PIE_STATIC),13)
	$(call run_expect,/usr/bin/busybox false,1)
	$(call run_expect,/usr/bin/busybox true,0)
	$(call run_expect,/usr/bin/busybox echo hi,0)
	$(call run_expect,/usr/bin/busybox ls /tmp,0)

# Not a test, it shows the loader's syscalls while it runs /bin/true
trace: $(LOADER)
	strace ./$(LOADER) /bin/true

clean:
	rm -f $(LOADER) $(SAMPLES)
