; ET_EXEC is awkward because fixed PT_LOAD mappings can stomp on the running
; loader. The way around that is to copy this trampoline to scratch memory,
; jump there in the child, and only then start claiming fixed addresses.
;
; Do not quote me on this, but I think this is the only way to do an ET_EXEC
; fork + exec without another helper program.
;
; Input:
;   rdi = EXEC_CTX written by the parent path in forkTransformExec
;
;   1. map PT_LOAD at fixed addresses
;   2. apply the small supported relocation subset
;   3. restore the stack we already built
;   4. jump to the target entry or the interpreter

execTrampolineStart:
    mov rbx, rdi                                        ; EXEC_CTX pointer, kept in a callee register since rdi becomes a syscall argument almost immediately
    mov r12, [rbx + EXEC_CTX.file_ptr]                  ; file_ptr is the parent's already mapped/staged copy of the target file's bytes
    mov r13, [rbx + EXEC_CTX.phoff]
    add r13, r12                                        ; r13 walks the phdr table directly inside the target's own bytes, no separate scratch copy needed here
    mov r14, [rbx + EXEC_CTX.phentsize]
    mov r15, [rbx + EXEC_CTX.phnum]
    .loop:
        test r15, r15
        jz .done
        cmp dword [r13 + PHDR.type], PT_LOAD            ; only PT_LOAD segments get mapped, PT_INTERP/PT_NOTE/etc. are irrelevant to this pass
        jne .next
        mov r10, [r13 + PHDR.memsz]
        test r10, r10                                   ; a zero sized segment needs no mapping at all
        jz .next
        mov r11, [r13 + PHDR.vaddr]
        mov r9, r11
        and r11, -PAGE_SIZE
        sub r9, r11                                     ; r9 is the offset from the page boundary to the vaddr, a segment need not start on one
        add r10, r9                                     ; extends the mapped length to cover that leading partial page too
        add r10, PAGE_SIZE - 1
        and r10, -PAGE_SIZE
        mov rdi, r11
        mov rsi, r10
        mov rdx, PROT_READ or PROT_WRITE                ; mapped RW first so the copy and bss fill below can write, mprotect narrows it further down
        mov r8, -1                                      ; ignored for an anonymous mapping, same convention used throughout this loader
        push r13                                        ; r13/r14/r15 are the outer phdr loop's state (current phdr, stride, remaining count), carried across the mmap call so .next can resume
        push r14
        push r15
        mov r10, MAP_PRIVATE or MAP_ANON or MAP_FIXED   ; MAP_FIXED is required here, the target's own vaddrs aren't negotiable like a normal reservation
        xor r9, r9
        mov rax, SYS_MMAP
        syscall
        pop r15
        pop r14
        pop r13
        test rax, rax
        js .fail                                            ; a failed mapping here is unrecoverable, there's no fallback address to retry at

        ; Copy the bytes that exist on disk, then zero the
        ; tail if this segment grows into bss.
        mov rdi, [r13 + PHDR.vaddr]                     ; destination is the segment's vaddr, not the page aligned one used for the mapping above
        mov rcx, [r13 + PHDR.filesz]
        mov rsi, r12
        add rsi, [r13 + PHDR.offset]                    ; source is the byte offset inside file_ptr where this segment's on-disk contents begin
        rep movsb
        mov rcx, [r13 + PHDR.memsz]
        sub rcx, [r13 + PHDR.filesz]                    ; whatever memsz exceeds filesz by is the bss tail, zeroed below instead of copied
        jbe .setProt
        mov rdi, [r13 + PHDR.vaddr]
        add rdi, [r13 + PHDR.filesz]
        xor eax, eax
        rep stosb

        ; RW was only for setup. Now the segment gets the permissions it really
        ; asked for
        .setProt:
        mov r11, [r13 + PHDR.vaddr]                     ; recomputing the same page aligned range as the mmap above rather than keeping it around
        mov r9, r11
        and r11, -PAGE_SIZE
        sub r9, r11
        mov r10, [r13 + PHDR.memsz]
        add r10, r9
        add r10, PAGE_SIZE - 1
        and r10, -PAGE_SIZE
        mov r8d, [r13 + PHDR.flags]                     ; PF_R/PF_W/PF_X bit positions don't line up with PROT_READ/WRITE/EXEC, hence the translation
        ELF_FLAGS_TO_PROT r8d, edx
        mov rdi, r11
        mov rsi, r10
        mov rax, SYS_MPROTECT                           ; segment was mapped RW only to allow the copy/zero above, now locked to what the phdr actually requests
        syscall
        test rax, rax
        js .fail
        .next:
        add r13, r14
        dec r15
        jmp .loop

    ; Static ET_EXEC only needs the SHDR IRELATIVE cleanup.
    ; The richer relocation story lives in the normal ET_DYN path
    .done:
    mov r13, [rbx + EXEC_CTX.shoff]                     ; second walk, this time over section headers rather than program headers
    add r13, r12
    mov r14, [rbx + EXEC_CTX.shentsize]
    mov r15, [rbx + EXEC_CTX.shnum]
    .shloop:
        test r15, r15
        jz .jumpEntry
        cmp dword [r13 + SHDR.type], SHT_RELA           ; only RELA sections can hold the IRELATIVE entries being hunted for here
        jne .shnext
        mov r10, [r13 + SHDR.entsize]
        test r10, r10                                   ; a zero entsize would fault the div below, skip such degenerate sections
        jz .shnext
        mov r11, [r13 + SHDR.offset]
        add r11, r12
        mov rcx, [r13 + SHDR.size]
        xor rdx, rdx
        mov rax, rcx
        div r10                                         ; turns the section's byte size into an entry count using its own entsize, not sizeof.RELA
        mov rcx, rax
        .relaloop:
            test rcx, rcx
            jz .shnext
            mov rax, [r11 + RELA.info]
            and eax, 0xffffffff                     ; low bits hold the relocation type
            cmp eax, R_X86_64_IRELATIVE
            jne .relanext
            mov rdi, [r11 + RELA.offset]                ; the value that lands at this address comes from calling the resolver in rax below, not straight from the table
            mov rax, [r11 + RELA.addend]                ; addend is the ifunc resolver's address for an IRELATIVE entry, not a plain pointer value
            push rcx                                    ; every bit of surrounding loop state gets saved, the resolver is arbitrary code with no promise about what it preserves
            push r11
            push r13
            push r14
            push r15
            call rax                                    ; invokes the image's own resolver to get the real relocated value
            pop r15
            pop r14
            pop r13
            pop r11
            pop rcx
            mov [rdi], rax                              ; rax on return is the resolver's actual result, that's what is stored
            .relanext:
            add r11, r10
            dec rcx
            jmp .relaloop
        .shnext:
        add r13, r14
        dec r15
        jmp .shloop

    ; The parent already built the target stack, so the trampoline just has to
    ; restore it
    .jumpEntry:
    mov rsp, [rbx + EXEC_CTX.stack_ptr]                 ; argv/envp/auxv were already laid out on this stack by the parent, the trampoline never builds it itself
    xor ebp, ebp
    xor eax, eax
    xor edx, edx                                        ; rdx is the ABI mandated atexit registration pointer handed to the entry point, cleared since there is none
    cmp qword [rbx + EXEC_CTX.has_interp], 0            ; whether the target needs ld.so or can start directly at its own entry
    jne .jumpInterp
    mov r11, [rbx + EXEC_CTX.entry]                     ; jumping through a register rather than a direct jmp since this address is only known at runtime
    jmp r11
    .jumpInterp:
    mov r11, [rbx + EXEC_CTX.interp_entry]              ; hands off to the interpreter's real entry, already relocated by the ET_DYN path elsewhere
    jmp r11

    .fail:
    mov edi, 1                                          
    mov eax, SYS_EXIT
    syscall

execTrampolineEnd:
execTrampolineSize = execTrampolineEnd - execTrampolineStart
