; Direct entry TLS setup (I hated this very much, took me like 1 year of work)
; This file owns the two ABI sensitive chores nobody really gets for free here:
;   * fake just enough TLS for direct entry PT_TLS binaries
;   * rebuild a kernel like initial stack with patched auxv values
prepareTlsAndStack:
    ; If PT_INTERP is in charge, ld-linux will sort TLS out later. The manual
    ; bootstrap below is only for the direct entry paths where we jmp in
    ; ourselves
    cmp byte [hasInterp], 0
    jne prepareStackImage
    cmp byte [hasTls], 0                                        ; no PT_TLS segment means nothing here to fake
    je prepareStackImage
    lea rsi, [dbgTlsMsg]
    mov rdx, dbgTlsMsgLen
    call debugWrite
    ; PT_TLS alignment can be zero or just plain tiny. We normalize it here so
    ; the synthetic layout has a sane x64 baseline
    mov rax, [tlsAlign]                                         ; raw phdr value, some toolchains leave this at 0
    test rax, rax
    jnz .tlsAlignReady
    mov rax, 1                                                  ; 0 and 1 are both "no real alignment", clamp before the size check below
    .tlsAlignReady:
    cmp rax, 16
    jae .tlsAlignSized
    mov rax, 16                                                 ; x64 wants the TLS block itself at least 16 byte aligned regardless of what the phdr claims
    .tlsAlignSized:
    ; Layout is:
    ;   [TLS block][TCB][small DTV]
    ; Then FS points at the TCB. Minimal, yes, but enough for the direct entry
    ; cases we care about here
    mov [tlsAlignWork], rax
    mov rcx, [tlsMemsz]
    add rcx, TLS_TCB_SIZE + TLS_DTV_SIZE                        ; room for TCB and DTV right after the copied TLS data
    add rcx, rax  ; folds the worst case alignment slack into the mmap request
    add rcx, 15  ; rounding bias paired with the mask two lines down
    and rcx, -16                                                ; round the mmap length up so the later alignment math has slack to work with
    mov rdi, 0
    mov rsi, rcx
    mov rdx, PROT_READ or PROT_WRITE
    mov r10, MAP_PRIVATE or MAP_ANON  ; ANON here, no backing file, matches the -1 fd two lines down
    mov r8, -1                                                  ; must be -1 for MAP_ANON, a stray fd here is a classic copy paste bug
    xor r9, r9
    mov rax, SYS_MMAP
    syscall
    test rax, rax
    js mmapFailed
    ; Place the TCB right after the TLS block, align it up, and keep the block
    ; itself immediately before it. That matches the x64 model glibc and
    ; static PIE startup code expect closely enough for our needs
    mov rdi, rax
    add rdi, [tlsMemsz]  ; provisional TCB position before the alignment rounding two lines below
    mov rax, [tlsAlignWork]
    dec rax  ; turns the alignment value into a mask of the low bits to clear
    add rdi, rax                                                ; classic round up to alignment trick, rax is (align - 1) here
    not rax
    and rdi, rax
    mov [tlsTcb], rdi
    mov rax, rdi  ; becomes tlsBlock's address once memsz is subtracted below
    sub rax, [tlsMemsz]                                         ; block sits directly below the TCB with no gap between them
    mov [tlsBlock], rax
    mov rdi, rax  ; copy destination now, the branch below only decides where the source comes from
    cmp word [ehdr.type], ET_EXEC
    jne .tlsCopyFromMapped
    ; ET_EXEC has not been remapped yet at this point, so its TLS initializer
    ; still has to come from the staged file buffer
    lea rsi, [buffer]
    add rsi, [tlsOffset]
    jmp .tlsCopyReady
    .tlsCopyFromMapped:
    mov rsi, [baseAddr]  ; ET_DYN/interp case, initializer now comes from the already-mapped image instead of the staged file
    add rsi, [tlsVaddr]
    .tlsCopyReady:
    ; Copy the initializer bytes, then zero the tail if there is one
    mov rcx, [tlsFilesz]  ; rep movsb count, only the on-disk part of the TLS block gets copied here
    rep movsb
    mov rcx, [tlsMemsz]
    sub rcx, [tlsFilesz]                                        ; anything past filesz is bss-like and must read as zero, not whatever mmap gave us
    xor eax, eax
    rep stosb
    mov rdi, [tlsTcb]
    mov rax, rdi
    mov [rdi], rax                                              ; TCB self pointer, %fs:0 has to read back its own address per the ABI
    lea rax, [rdi + TLS_TCB_SIZE + 16]  ; where the DTV gets seeded a few lines down
    mov [rdi + 8], rax  ; DTV pointer field of the TCB, read by the TLS access fast path
    mov [rdi + 16], rdi                                         ; second self pointer slot some libcs also probe, cheap to fill in
    ; Seed a tiny DTV that describes one TLS module starting at tlsBlock
    lea rsi, [rdi + TLS_TCB_SIZE]
    mov qword [rsi], 1  ; generation counter, 1 is fine since this DTV is never regenerated
    mov qword [rsi + 8], 0
    mov qword [rsi + 16], 1  ; module id, matches the single module this synthetic DTV describes
    mov qword [rsi + 24], 0
    mov rax, [tlsBlock]
    mov [rsi + 32], rax                                         ; the one slot that actually matters, block pointer for module 1
    mov qword [rsi + 40], 0
    mov rdi, ARCH_SET_FS                                        ; the only userspace way to point %fs at our synthetic TCB
    mov rsi, [tlsTcb]
    mov rax, SYS_ARCH_PRCTL
    syscall
    test rax, rax
    js archPrctlFailed

prepareStackImage:
    ; Rebuild a kernel like initial stack in loader-owned memory:
    ;   argc
    ;   argv[]
    ;   NULL
    ;   envp[]
    ;   NULL
    ;   auxv[]
    ; We also duplicate the pointed to strings and aux payloads so the loaded
    ; program does not keep pointers into the loader's own stack by accident
    lea rsi, [dbgStackBuildMsg]
    mov rdx, dbgStackBuildMsgLen
    call debugWrite
    mov rbx, [targetArgv]
    mov rcx, [targetArgc]
    lea rdx, [rbx + rcx * 8 + 8]                                ; skip past argv's own pointers plus their NULL terminator to land on envp[0]
    mov [targetEnvp], rdx
    mov rsi, rdx                                                ; envp carries no count from the kernel, walk forward to find its NULL below
    .findAuxv:
        mov rax, [rsi]
        add rsi, 8
        test rax, rax
        jnz .findAuxv
    mov [targetAuxv], rsi                               ; rsi already sits one slot past envp's NULL, exactly where auxv begins
    mov rdx, [targetEnvp]
    xor rcx, rcx
    .countEnvp:
        mov rax, [rdx]
        add rdx, 8
        inc rcx
        test rax, rax
        jnz .countEnvp
    dec rcx                                                     ; that last increment counted the NULL terminator itself, back it out
    mov [targetEnvc], rcx
    mov rsi, [targetAuxv]
    xor rcx, rcx
    .countAuxv:
        mov rax, [rsi]
        add rsi, 16                                             ; auxv entries are tag/value pairs, twice the width of the envp/argv pointer slots
        inc rcx
        test rax, rax
        jnz .countAuxv
    mov [targetAuxc], rcx
    xor rcx, rcx
    ; First count how many string bytes we are about to duplicate. If the
    ; reserved stack storage is too small, bail out now instead of half
    ; building a stack
    mov rsi, [targetArgv]
    mov rdx, [targetArgc]                           ; rdx is reused purely as this loop's down counter, unrelated to its other duties in this file
    .countArgStrings:
        test rdx, rdx
        jz .countEnvStrings
        mov rdi, [rsi]
        .countArgStringBytes:
            inc rcx
            mov al, [rdi]
            inc rdi
            test al, al
            jnz .countArgStringBytes
        add rsi, 8
        dec rdx
        jmp .countArgStrings
    .countEnvStrings:
    mov rsi, [targetEnvp]
    mov rdx, [targetEnvc]                            ; same down counter reuse as the argv string count above
    .countEnvStringsLoop:
        test rdx, rdx
        jz .countStringsDone
        mov rdi, [rsi]
        .countEnvStringBytes:
            inc rcx
            mov al, [rdi]
            inc rdi
            test al, al
            jnz .countEnvStringBytes
        add rsi, 8
        dec rdx
        jmp .countEnvStringsLoop
    .countStringsDone:
    mov [totalStringBytes], rcx
    cmp rcx, STACK_STRING_SIZE
    jg stackStorageTooSmall
    mov rax, [stackAddr]
    add rax, STACK_STORAGE_SIZE                                 ; strings live in their own fixed region right after the pointer table area
    mov [stringWritePtr], rax
    mov rax, [stackAddr]
    add rax, STACK_SIZE                                         ; STACK_SIZE is the whole reservation, table build works backward from its top
    and rax, -16                                              ; same 16 byte floor the parity fixup below assumes for the eventual entry rsp
    mov rcx, [targetEnvc]
    add rcx, [targetArgc]                                       ; total pointer table entries feeds the parity check below, argc gets its own slot separately
    ; The stack is built downward from the top of the mapping. The exact top
    ; alignment differs a little between direct entry and PT_INTERP paths, so
    ; we settle that before laying out the tables
    ; keeps entry rsp aligned to 16 bytes, interp flips which parity needs the extra word
    cmp byte [hasInterp], 0
    jne .stackTopInterp
    test rcx, 1
    jz .stackTopReady
    sub rax, 8
    jmp .stackTopReady
    .stackTopInterp:
    test rcx, 1
    jnz .stackTopReady
    sub rax, 8
    .stackTopReady:
    mov [newStackPtr], rax
    ; Pointer tables go downward from the top:
    ;   auxv, then envp, then argv, then argc
    ; Copied strings and aux payloads grow upward from stringWritePtr.
    ; That split keeps ownership obvious and avoids leaving target pointers
    ; aimed at the loaders original entry stack
    mov rdi, [newStackPtr]
    mov rcx, [targetAuxc]
    shl rcx, 4                                                  ; 16 bytes per auxv entry, matches the stride used when counting them above
    sub rdi, rcx                                                ; rcx here is already a byte count from the shift above, not the raw entry count
    mov [auxvDst], rdi
    mov rsi, [targetAuxv]
    mov rcx, [targetAuxc]
    .copyAuxv:
        ; Auxv copy/patch pass.
        ; Most entries survive unchanged, but some values must be rewritten
        ; because the loader changed image placement, entry routing, or the
        ; storage backing the strings/payloads they point at
        mov rax, [rsi]
        mov r8, [rsi + 8]                                       ; default is the untouched source side value, dispatch below overrides it case by case
        cmp rax, AT_PHDR
        jne .auxNotPhdr
        mov r8, [phdrRuntime]                                   ; only meaningful if a PT_LOAD happened to contain the phdr table, resolved back in the exec scan
        jmp .auxStore
        .auxNotPhdr:
        cmp rax, AT_PHENT
        jne .auxNotPhent
        movzx r8, word [ehdr.phentsize]                     ; passed through unchanged, phentsize is identical between the staged file and the runtime image
        jmp .auxStore
        .auxNotPhent:
        cmp rax, AT_PHNUM
        jne .auxNotPhnum
        movzx r8, word [ehdr.phnum]                          ; same pass-through reasoning as AT_PHENT just above
        jmp .auxStore
        .auxNotPhnum:
        cmp rax, AT_BASE
        jne .auxNotBase
        mov r8, [interpBaseAddr]                                ; ld.so reads this to find its own load address, stays zero when there is no interpreter
        jmp .auxStore
        .auxNotBase:
        cmp rax, AT_ENTRY
        jne .auxNotEntry
        mov r8, [baseAddr]
        add r8, [ehdr.entry]                                    ; the target's real entry, some runtimes read this directly instead of trusting rip at startup
        jmp .auxStore
        .auxNotEntry:
        cmp rax, AT_EXECFN
        jne .auxNotExecfn
        mov r8, [targetPath]                                    ; placeholder for now, patchExecfnAuxv below overwrites this once argv[0] has been copied
        jmp .auxStore
        .auxNotExecfn:
        cmp rax, AT_RANDOM
        jne .auxNotRandom
        ; AT_RANDOM points at 16 random bytes (not a C string) so copy the
        ; payload as is and then patch the auxv value to the copied address
        push rcx  ; outer auxv loop counter, must survive the byte copy below
        push rax  ; still holds the auxv tag, needed again once this falls through to .auxStore
        mov r9, [stringWritePtr]
        mov [rdi + 8], r9
        mov r10, [rsi + 8]
        mov rcx, 16                                             ; fixed by the kernel ABI, always exactly 16 bytes regardless of arch
        .copyAuxRandom:
            mov dl, [r10]
            mov [r9], dl
            inc r9
            inc r10
            loop .copyAuxRandom
        mov [stringWritePtr], r9
        pop rax
        pop rcx
        mov r8, [rdi + 8]
        jmp .auxStore
        .auxNotRandom:
        cmp rax, AT_PLATFORM
        je .copyAuxString
        cmp rax, AT_BASE_PLATFORM
        jne .auxStore
        .copyAuxString:
        ; These auxv entries point at NUL terminated strings that also need to
        ; move onto the target stack image
        push rcx                            ; this loop never touches rcx either, saved only to stay symmetric with the AT_RANDOM case above
        push rax                            ; carries the auxv tag forward to .auxStore the same way the AT_RANDOM branch does
        mov r9, [stringWritePtr]
        mov [rdi + 8], r9
        mov r10, [rsi + 8]
        .copyAuxCString:
            mov dl, [r10]
            mov [r9], dl
            inc r9
            inc r10
            test dl, dl
            jnz .copyAuxCString
        mov [stringWritePtr], r9
        pop rax
        pop rcx
        mov r8, [rdi + 8]
        .auxStore:
        mov [rdi], rax
        mov [rdi + 8], r8
        add rsi, 16                          ; next auxv entry, same 16 byte stride used everywhere else in this loop
        add rdi, 16
        dec rcx
        jnz .copyAuxv
    mov rdi, [auxvDst]
    mov rax, [targetEnvc]
    inc rax
    shl rax, 3                                                  ; pointer sized slots, the envp equivalent of the *16 stride used for auxv above
    sub rdi, rax                                                ; rax is envp's byte sized table length, computed the same way argv's is below
    mov [envpDst], rdi
    mov rdi, [envpDst]
    mov rsi, [targetEnvp]
    mov rcx, [targetEnvc]
    .copyEnvStrings:
        ; Environment vector rewrite.
        ; Each envp[i] pointer is rewritten to point at a copied string owned
        ; by the synthetic stack mapping instead of the loader's original
        ; startup stack
        test rcx, rcx
        jz .copyEnvStringsDone
        mov r8, [stringWritePtr]
        mov [rdi], r8
        mov r9, [rsi]                                       ; r9 walks the source string while r8 walks the destination copy, independent lengths are fine
        .copyOneEnvString:
            mov al, [r9]
            mov [r8], al
            inc r8
            inc r9
            test al, al
            jnz .copyOneEnvString
        mov [stringWritePtr], r8
        add rdi, 8
        add rsi, 8
        dec rcx
        jmp .copyEnvStrings
    .copyEnvStringsDone:
    mov qword [rdi], 0                                          ; NULL terminates envp, argv gets the same treatment further down
    mov rdi, [envpDst]
    mov rax, [targetArgc]
    inc rax
    shl rax, 3                                              ; same pointer stride multiply used for envp's table just above
    sub rdi, rax
    mov [argvDst], rdi
    mov rdi, [argvDst]
    mov rsi, [targetArgv]
    mov rcx, [targetArgc]
    .copyArgStrings:
        ; Argument vector rewrite.
        ; argv is like envp: rewrite pointer slots downward,
        ; copy actual string bytes upward into target-owned storage.
        test rcx, rcx
        jz .copyArgStringsDone
        mov r8, [stringWritePtr]
        mov [rdi], r8
        mov r9, [rsi]                                    ; same independent src/dst pointer split as the envp copy above
        .copyOneArgString:
            mov al, [r9]
            mov [r8], al
            inc r8
            inc r9
            test al, al
            jnz .copyOneArgString
        mov [stringWritePtr], r8
        add rdi, 8
        add rsi, 8
        dec rcx
        jmp .copyArgStrings
    .copyArgStringsDone:
    mov qword [rdi], 0                                  ; argv terminated the same way envp was above
    mov rax, [argvDst]
    mov rax, [rax]                                              ; argv[0] specifically, the pointer the copy loop above just wrote
    mov [targetPathNew], rax
    mov rsi, [auxvDst]
    mov rcx, [targetAuxc]
    .patchExecfnAuxv:
        ; AT_EXECFN should reference the copied argv[0] string, not the old
        ; pointer into the loader's original stack
        test rcx, rcx
        jz .patchExecfnDone
        mov rax, [rsi]
        cmp rax, AT_EXECFN
        jne .nextExecfnAuxv
        mov rax, [targetPathNew]
        mov [rsi + 8], rax
        jmp .patchExecfnDone
        .nextExecfnAuxv:
        add rsi, 16
        dec rcx
        jmp .patchExecfnAuxv
    .patchExecfnDone:
    ; After argv/envp/auxv are laid out, prepend argc immediately below them.
    ; That final pointer is what the target entry code will observe in rsp
    mov rdi, [argvDst]
    sub rdi, 8                                                  ; argc gets its own qword slot directly below argv[0]'s pointer
    mov rax, [targetArgc]
    mov [rdi], rax
    mov [newStackPtr], rdi                                      ; this final value is what ends up in the child's rsp at entry
    ; Final handoff selection.
    ; After this point the stack image is complete. We can close the staged
    ; file and choose the final entry mechanism:
    ;   * ET_EXEC -> fork + scratch trampoline
    ;   * PT_INTERP -> jmp into ld-linux
    ;   * otherwise -> jmp directly to the main executable entry point
    ; From this point on the staged file descriptor is no longer needed. All
    ; target bytes that matter have already been copied into anonymous mappings
    mov rdi, [targetFd]
    mov rax, SYS_CLOSE
    syscall
    test rax, rax
    js closeFailed
    ; ET_EXEC targets must switch through the child trampoline so they can
    ; claim fixed virtual addresses without destroying the running loader
    cmp word [ehdr.type], ET_EXEC
    je forkTransformExec
    cmp byte [hasInterp], 0
    jne .jumpInterp
    mov r11, [baseAddr]
    add r11, [ehdr.entry]                                       ; no interpreter case, jump straight to the target's own entry point
    lea rsi, [dbgJumpMainMsg]
    mov rdx, dbgJumpMainMsgLen
    mov rax, r11
    call debugPrintHexLine
    ENTER_PREPARED_IMAGE newStackPtr, r11
    .jumpInterp:
    mov r11, [interpBaseAddr]
    add r11, [interpEhdr.entry]                               ; hand off to ld-linux's own entry, not the target's, so it can finish real relocation and TLS
    lea rsi, [dbgJumpInterpMsg]
    mov rdx, dbgJumpInterpMsgLen
    mov rax, r11
    call debugPrintHexLine
    ENTER_PREPARED_IMAGE newStackPtr, r11
