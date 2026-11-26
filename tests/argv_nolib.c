/*
 * Small no-libc argv probe
 *
 * The loader rebuilds argc/argv by hand, so this test reads the entry stack
 * directly and complains the moment anything looks off
 *
 * Build it twice, something like:
 *   - ET_EXEC -> /tmp/argv_exec_c
 *   - ET_DYN  -> /tmp/argv_pie_c
 */

#ifndef EXPECTED_SELF
#error "EXPECTED_SELF must be defined by the Makefile"
#endif

static long sys_write(int fd, const char *buf, unsigned long count)
{
  long ret;
  asm volatile(
      "mov $1, %%rax\n"
      "syscall\n"
      : "=a"(ret)
      : "D"(fd), "S"(buf), "d"(count)
      : "rcx", "r11", "memory");
  return ret;
}

static void sys_exit(int code)
{
  asm volatile(
      "mov $60, %%rax\n"
      "syscall\n"
      :
      : "D"(code)
      : "rax", "rcx", "r11", "memory");
  __builtin_unreachable();
}

static int streq(const char *left, const char *right)
{
  while (*left && *right)
  {
    if (*left != *right)
    {
      return 0;
    }
    left++;
    right++;
  }
  return *left == *right;
}

/*
 * A pointer table needs RELATIVE relocations in the PIE build. Nothing in this
 * binary relocates itself, so the check below only passes if halfexec applied
 * every entry, not just the first one
 */
static const char *const expected[] = {EXPECTED_SELF, "alpha", "beta"};

static void real_start(long *stack_words)
{
  /*
   * Linux drops us in with rsp -> argc, argv[0], argv[1], ...
   * Reading that directly keeps this test free from any C runtime stuff
   */
  long argc;
  char **argv;

  /* The kernel enters every program with rsp 16 byte aligned */
  if ((unsigned long)stack_words & 15)
  {
    static const char bad_align[] = "stack misaligned\n";
    sys_write(1, bad_align, sizeof(bad_align) - 1);
    sys_exit(8);
  }

  argc = stack_words[0];
  argv = (char **)&stack_words[1];

  if (argc != 3)
  {
    static const char bad_argc[] = "argc mismatch\n";
    sys_write(1, bad_argc, sizeof(bad_argc) - 1);
    sys_exit(9);
  }

  for (int i = 0; i < 3; i++)
  {
    if (!streq(argv[i], expected[i]))
    {
      static const char bad_argv[] = "argv mismatch\n";
      sys_write(1, bad_argv, sizeof(bad_argv) - 1);
      sys_exit(9);
    }
  }

  static const char ok[] = "argv ok\n";
  sys_write(1, ok, sizeof(ok) - 1);
  sys_exit(0);
}

/*
 * _start has to keep the original entry rsp intact. A normal prologue would
 * already disturb it before the test are able to check
 */
__attribute__((naked, noreturn)) void _start(void)
{
  /* call and not jmp, so real_start sees the normal function entry alignment */
  asm volatile(
      "mov %rsp, %rdi\n"
      "call real_start\n");
}
