; PT_INTERP loading and mapping. Also a bit confusing, heavily commented for my
; own sake
; Map its PT_LOAD segments, jump to its entry point, and let it do the rest
loadInterp:
    ; PT_INTERP is just another ET_DYN, only this one gets to take over
    lea rsi, [dbgLoadInterpMsg]
    mov rdx, dbgLoadInterpMsgLen
    call debugWrite                                         ; gated on HALFEXEC_DEBUG at runtime and preserves every register, safe to sprinkle in without clobber bookkeeping
    mov rdi, [interpPathPtr]                                ; path string was already resolved out of the target's phdrs earlier
    test rdi, rdi
    jz unsupportedInterp                                    ; a null path here means no PT_INTERP was ever recorded
    mov rsi, O_RDONLY
    xor rdx, rdx
    mov rax, SYS_OPEN
    syscall
    test rax, rax
    js openFailed                                             ; no interpreter means no way to run a dynamically linked binary, this is fatal
    mov [interpFd], rax                                      ; kept around, still needed for the pread/read/close calls further down
    mov rdi, rax
    lea rsi, [interpStat]
    mov rax, SYS_FSTAT
    syscall
    test rax, rax
    js fstatFailed
    cmp qword [interpStat.st_size], BUFFER_SIZE             ; ld.so is normally a few hundred KB, this just bounds the fixed staging buffer
    jg fileTooLarge
    mov rdi, [interpFd]
    lea rsi, [interpEhdr]
    mov rdx, sizeof.EHDR
    xor r10, r10                                            ; pread64 offset, reading the header from the very start of the file
    mov rax, SYS_PREAD64
    syscall
    cmp rax, sizeof.EHDR                                    ; pread64 can return short, don't trust any header field until the full size landed
    jne headerReadFailed
    cmp [interpEhdr.magic], 0x464c457f                      ; 0x464c457f is ".ELF" read as a little endian dword
    jne invalidElf
    cmp [interpEhdr.class], ELFCLASS64                      ; only 64 bit ELF is supported, a 32 bit ld.so needs a different loader entirely
    jne invalidArch
    cmp [interpEhdr.data], ELFDATA2LSB                      ; big-endian ELF isn't something worth expecting on x64
    jne invalidElf
    cmp word [interpEhdr.machine], EM_X86_64                ; rules out a other arch interpreter
    jne invalidArch
    cmp dword [interpEhdr.version], EV_CURRENT              ; effectively always 1, but a mismatch usually means a corrupt or handcrafted header
    jne invalidElf
    cmp word [interpEhdr.type], ET_DYN                      ; a real ld.so is always position independent, ET_EXEC would be nonsense here
    jne unsupportedInterp
    ; If these do not match, we are done here.
    cmp word [interpEhdr.ehsize], sizeof.EHDR                 ; mismatch would mean a foreign or corrupt ELF header size
    jne invalidLayout
    cmp word [interpEhdr.phentsize], sizeof.PHDR              ; a mismatch here would mean our PHDR struct layout doesn't match what's on disk
    jne invalidLayout

    mov rdi, [interpFd]
    lea rsi, [interpBuffer]                                 ; staged in a flat buffer rather than mmap'd from the file, keeps the phdr math below independent of the final placement
    mov rdx, [interpStat.st_size]                           ; read the whole interpreter in one go rather than mmap it, keeps both phdr passes below simple
    mov rax, SYS_READ
    syscall
    cmp rax, [interpStat.st_size]
    jne fileReadFailed                                      ; a short read would leave the tail of the staging buffer stale
    ; Find the whole PT_LOAD span, then reserve one bias window and map into it
    mov qword [interpImageMinVaddr], -1                     ; -1 sentinel so the first PT_LOAD always wins the min comparison below
    mov qword [interpImageMaxVaddr], 0                      ; zero is a safe low start, every real vaddr will land higher
    lea rbx, [interpBuffer]
    add rbx, [interpEhdr.phoff]                             ; rbx now walks the raw phdr table inside the staging buffer, not the mapped image
    xor ecx, ecx
    movzx ecx, word [interpEhdr.phnum]                      ; phnum bounds both this scan pass and the mapping pass below, they share the same count
    .scanInterpLoop:
        test rcx, rcx
        jz .scanInterpDone
        mov rsi, rbx
        lea rdi, [phdr]                                    ; phdr is one shared scratch struct, reused each iteration since only one entry is needed at a time
        push rcx                                            ; rep movsb below needs its own count in rcx, save the real loop counter first
        mov ecx, sizeof.PHDR
        rep movsb
        pop rcx
        cmp dword [phdr.type], PT_LOAD                      ; PT_NOTE, PT_GNU_STACK and the rest don't factor into the load span at all
        jne .scanInterpNext
        cmp qword [phdr.memsz], 0                           ; a zero sized PT_LOAD contributes nothing to the span, some linkers emit these
        je .scanInterpNext
        ; page align this segment
        mov rax, [phdr.vaddr]
        and rax, -PAGE_SIZE
        mov rdx, [phdr.vaddr]
        add rdx, [phdr.memsz]
        add rdx, PAGE_SIZE - 1
        and rdx, -PAGE_SIZE
        UPDATE_LOAD_SPAN rax, rdx, interpImageMinVaddr, interpImageMaxVaddr
        .scanInterpNext:
        movzx rax, word [interpEhdr.phentsize]              ; the authoritative per entry stride, not sizeof.PHDR, in case of extra vendor fields on disk
        add rbx, rax
        dec rcx
        jmp .scanInterpLoop
    .scanInterpDone:
    mov rax, [interpImageMinVaddr]
    cmp rax, -1                                             ; sentinel never got overwritten means we found no PT_LOAD at all
    je invalidElf
    mov rdx, [interpImageMaxVaddr]
    sub rdx, rax
    mov [interpImageSpanSize], rdx                          ; length of the single anonymous reservation made below
    ; Reserve the entire PT_LOAD span first and derive the interpreter load
    ; bias from that reservation
    xor rdi, rdi                                            ; let the kernel pick the address, we only care about the size right now
    mov rsi, [interpImageSpanSize]
    mov rdx, PROT_READ or PROT_WRITE                        ; permissions barely matter here, every byte gets its own mapping and protection below
    mov r10, MAP_PRIVATE or MAP_ANON
    mov r8, -1                                              ; fd is ignored for an anonymous mapping, this is only a placeholder reservation
    xor r9, r9
    mov rax, SYS_MMAP
    syscall
    test rax, rax
    js mmapFailed
    mov rdx, [interpImageMinVaddr]
    sub rax, rdx                                          ; this delta is the load bias, add it to every raw vaddr from the interpreter's phdrs to get a real address
    mov [interpBaseAddr], rax
    lea rsi, [dbgInterpBaseMsg]
    mov rdx, dbgInterpBaseMsgLen
    mov rax, [interpBaseAddr]
    call debugPrintHexLine                                  ; only fires with HALFEXEC_DEBUG set
    ; Interpreter PT_LOAD population.
    ; Each PT_LOAD gets mapped RW into the reserved interpreter span, copied
    ; from the staging buffer (zeroed if memsz > filesz), and tightened to the
    ; permissions requested by PF_*
    lea rbx, [interpBuffer]
    add rbx, [interpEhdr.phoff]
    xor ecx, ecx
    movzx ecx, word [interpEhdr.phnum]
    .mapInterpLoop:
        test rcx, rcx
        jz .mapInterpDone
        mov rsi, rbx
        lea rdi, [phdr]
        push rcx
        mov ecx, sizeof.PHDR
        rep movsb
        pop rcx
        cmp dword [phdr.type], PT_LOAD                      ; second pass over the same phdrs, this time actually mapping instead of just measuring
        jne .mapInterpNext
        cmp qword [phdr.memsz], 0                           ; same zero sized segment skip as the scan pass above
        je .mapInterpNext
        mov r12, rcx                                        ; syscall clobbers rcx (and r11), so the phdr counter has to live somewhere else for the calls below
        mov r15, [phdr.vaddr]
        and r15, -PAGE_SIZE
        push r15                                              ; r15 and r13 (aligned vaddr and mapped length) are needed again for mprotect further down
        mov r14, [phdr.vaddr]
        sub r14, r15                                          ; r14 is the offset from the page boundary to the real vaddr, a segment need not start on one
        mov r13, [phdr.memsz]
        add r13, r14
        add r13, PAGE_SIZE - 1
        and r13, -PAGE_SIZE
        push r13
        mov rdi, [interpBaseAddr]
        add rdi, r15
        mov rsi, r13
        mov rdx, PROT_READ or PROT_WRITE                    ; mapped RW regardless of the segment's real permissions, so the copy and bss fill below can write to it
        mov r10, MAP_PRIVATE or MAP_ANON or MAP_FIXED       ; MAP_FIXED is safe here since this address range came out of our own reservation above, not arbitrary space
        mov r8, -1                                          ; ignored for anonymous mappings, same as the reservation mmap above
        xor r9, r9
        mov rax, SYS_MMAP
        syscall
        test rax, rax
        js mmapFailed
        lea rsi, [dbgMapInterpMsg]
        mov rdx, dbgMapInterpMsgLen
        mov rax, [interpBaseAddr]
        add rax, r15
        call debugPrintHexLine
        mov r10, [phdr.offset]                              ; file offset of this segment's bytes inside the staging buffer
        mov r11, [phdr.vaddr]
        lea rsi, [interpBuffer + r10]                       ; source is the resident staging buffer, not the file, we already read the whole interpreter in above
        mov rdi, [interpBaseAddr]
        add rdi, r11
        mov rcx, [phdr.filesz]                              ; only filesz bytes actually exist on disk, the memsz remainder is bss handled below
        rep movsb
        mov r10, [phdr.memsz]
        mov r11, [phdr.filesz]
        cmp r10, r11
        jl .interpBssIgnore                                 ; memsz below filesz would be a malformed phdr, nothing sane to zero either way
        sub r10, r11
        mov rcx, r10
        mov r10, [phdr.vaddr]
        mov rdi, [interpBaseAddr]
        add rdi, r10
        add rdi, r11                                        ; rdi now points at the first byte past what came from disk
        xor eax, eax
        rep stosb                                           ; the (memsz - filesz) tail is bss, libc expects it zeroed rather than holding stale file bytes
        .interpBssIgnore:
        mov r8d, [phdr.flags]
        ELF_FLAGS_TO_PROT r8d, edx                          ; PF_R/PF_W/PF_X bit positions don't line up with PROT_READ/WRITE/EXEC
        .interpProtect:
        pop r13
        pop r15
        mov rdi, [interpBaseAddr]
        add rdi, r15
        mov rsi, r13
        mov rax, SYS_MPROTECT                               ; segment was mapped RW only so we could populate it, now lock it to what the phdr actually asked for
        syscall
        test rax, rax
        js mprotectFailed
        mov rcx, r12                                        ; restore the phdr counter stashed before the mmap/mprotect calls
        .mapInterpNext:
        movzx rax, word [interpEhdr.phentsize]
        add rbx, rax
        dec rcx
        jmp .mapInterpLoop
    .mapInterpDone:
    mov rdi, [interpFd]                                     ; everything needed from the interpreter is now staged or mapped, the fd can go
    mov rax, SYS_CLOSE
    syscall
    test rax, rax
    js closeFailed
    jmp prepareStackImage
