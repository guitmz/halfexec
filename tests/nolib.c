void exit_success()
{
  asm("mov $60, %rax\n" // sys_exit
      "mov $0, %rdi\n"  // status 0
      "syscall");
}

void print(const char *s, int count)
{
  // Just write to stdout and get out of the way
  asm("mov $1, %%rax\n" // sys_write
      "mov $1, %%edi\n" // stdout
      "mov %0, %%rsi\n" // buffer
      "mov %1, %%edx\n" // byte count
      "syscall\n"
      "mov %%rax, %0"
      :
      : "rm"(s), "rm"(count));
}

void _start()
{
  char string[] = "Hello World!\n";
  print(string, sizeof(string) - 1);
  exit_success();
}
