format ELF64 executable 3

segment readable executable
entry $

; asm smoke test for the plain ET_EXEC path
mov rax, 1
mov rdi, 1
mov rsi, msg
mov rdx, msgLen
syscall

mov rax, 60
xor rdi, rdi
syscall

segment readable
msg db 'Hello, world!', 10
msgLen = $ - msg
