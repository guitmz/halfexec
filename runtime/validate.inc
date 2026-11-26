; Main ELF validation and early dispatch. It ony checks the bits that matter
; for halfexec.
;
; Note: perhaps this could be refactored and included even earlier in the loader
;
; First make sure this even smells like the kind of ELF we want
    cmp [ehdr.magic], 0x464c457f
    jnz invalidElf
    cmp [ehdr.class], ELFCLASS64                          ; this loader only understands 64 bit ELF, 32 bit needs an entirely different phdr/ehdr layout
    jne invalidArch
    cmp [ehdr.data], ELFDATA2LSB                          ; big endian ELF is real on some architectures, just never on x64, so this mostly guards against corrupt input
    jne invalidElf
    cmp word [ehdr.machine], EM_X86_64                    ; machine field catches a cross architecture binary that class/data alone would let through
    jne invalidArch
    cmp dword [ehdr.version], EV_CURRENT                  ; guards against a phdr/shdr layout from some future ELF revision this loader was never tested against
    jne invalidElf
    ; The nastier PT_LOAD details wait until the scan/mapping passes later.
    cmp word [ehdr.ehsize], sizeof.EHDR                    ; rejects a truncated or hand crafted header before any offset inside it gets trusted
    jne invalidLayout
    cmp word [ehdr.phentsize], sizeof.PHDR                ; every phdr walk below assumes this exact stride, so a mismatch is caught here instead of corrupting the scan
    jne invalidLayout
    CHECK_PHDR_TABLE ehdr, [fstat.st_size], invalidLayout ; both scans below read phdrs straight out of buffer, so the table must lie inside the file

    ; Reset the bits of state that belong to one image so that the later phases
    ; are easier to trust when reading this months (years?) from now
    mov qword [interpPathPtr], 0
    mov qword [interpBaseAddr], 0                   ; zero here reads as no interpreter until PT_INTERP says otherwise during the scan below
    mov qword [imageMinVaddr], -1                   ; -1 is the sentinel meaning no PT_LOAD span has been seen yet
    mov qword [imageMaxVaddr], 0
    mov qword [imageSpanSize], 0

    ; This project only cares about ET_EXEC and ET_DYN
    cmp word [ehdr.type], ET_EXEC
    jne .notExec
    lea rsi, [dbgExecMsg]
    mov rdx, dbgExecMsgLen
    call debugWrite
    jmp execPrepare
    .notExec:
    cmp [ehdr.type], ET_DYN
    jne .notDyn
    lea rsi, [dbgDynMsg]
    mov rdx, dbgDynMsgLen
    call debugWrite
    jmp scanDynImage
    .notDyn:
    jmp unsupportedType                               ; anything besides ET_EXEC/ET_DYN (ET_REL, ET_CORE, etc) has no business being executed directly

; ET_EXEC pre scan.
; ET_EXEC wants fixed addresses. This pass just gathers the facts the child
; trampoline will need
execPrepare:
    mov [baseAddr], 0
    mov qword [phdrRuntime], 0
    mov byte [hasInterp], 0
    mov byte [hasDynamic], 0                             ; not read by the ET_EXEC path today, reset anyway so nothing leaks in from a previous image
    mov byte [hasTls], 0
    mov byte [stackProt], PROT_READ or PROT_WRITE        ; default permissions unless a PT_GNU_STACK phdr overrides them below
    lea rbx, [buffer]
    add rbx, [ehdr.phoff]                               ; rbx now walks the on disk phdr table directly, bounds checked by CHECK_PHDR_TABLE above
    xor ecx, ecx
    movzx ecx, word [ehdr.phnum]
    .scanExecLoop:
        test rcx, rcx
        jz .scanExecDone
        mov rsi, rbx
        lea rdi, [phdr]
        push rcx
        mov ecx, sizeof.PHDR                        ; rep movsb needs its own count in ecx, hence saving the loop counter around it
        rep movsb
        pop rcx

        ; PT_GNU_STACK only tells us what the final custom stack should look
        ; like permission wise
        cmp dword [phdr.type], PT_GNU_STACK
        jne .execNotStack
        mov r8d, [phdr.flags]
        ELF_FLAGS_TO_PROT r8d, edx                     ; turns PF_R/PF_W/PF_X bits into the PROT_* values mmap/mprotect actually expect
        .execStoreStackProt:
        mov [stackProt], dl
        .execNotStack:

        ; PT_INTERP is just a path string. Make sure it is in bounds and
        ; actually terminated
        cmp dword [phdr.type], PT_INTERP
        jne .execNotInterp
        cmp qword [phdr.filesz], 0
        je invalidInterpPath                        ; an empty interpreter path is not valid PT_INTERP data
        CHECK_FILE_RANGE [phdr.offset], [phdr.filesz], [fstat.st_size], invalidInterpPath
        mov byte [hasInterp], 1
        lea rsi, [dbgInterpFoundMsg]
        mov rdx, dbgInterpFoundMsgLen
        call debugWrite
        lea rax, [buffer]
        add rax, [phdr.offset]                         ; rax now points at the interpreter path string inside the staged file buffer
        mov rdx, [phdr.filesz]                         ; rdx and not rcx, since rcx is this loop's phdr counter
        dec rdx                                     ; phdr.filesz includes the NUL, so the last byte to check sits at filesz - 1
        cmp byte [rax + rdx], 0
        jne invalidInterpPath
        mov [interpPathPtr], rax
        .execNotInterp:

        ; PT_TLS gets recorded here and dealt with later, once we know which
        ; entry path gets chosen
        cmp dword [phdr.type], PT_TLS
        jne .execNotTls
        mov byte [hasTls], 1
        mov rax, [phdr.offset]
        mov [tlsOffset], rax
        mov rax, [phdr.filesz]                       ; the part of the TLS block backed by real file bytes, memsz below can be larger for the zero filled tail
        mov [tlsFilesz], rax
        mov rax, [phdr.memsz]
        mov [tlsMemsz], rax
        mov rax, [phdr.align]
        mov [tlsAlign], rax                          ; raw, unnormalized value here, prepareTlsAndStack is what clamps this later
        .execNotTls:

        ; If the PHDR table lives inside one PT_LOAD, we can later
        ; craft a AT_PHDR value
        cmp dword [phdr.type], PT_LOAD
        jne .execNotPhdrHost
        CHECK_PT_LOAD [fstat.st_size], invalidSegment ; the trampoline later copies these bytes without checking
        mov rax, [ehdr.phoff]
        cmp rax, [phdr.offset]
        jb .execNotPhdrHost                        ; phdr table must start at or after this segment's own file offset to be considered contained in it
        mov rdx, [phdr.offset]
        add rdx, [phdr.filesz]
        cmp rax, rdx
        jae .execNotPhdrHost                       ; and end before the segment's end too, otherwise the phdr table would straddle two segments
        mov rdx, [phdr.vaddr]
        add rdx, rax
        sub rdx, [phdr.offset]                        ; vaddr + (phoff - offset) turns the phdr table's file offset into its eventual runtime address
        mov [phdrRuntime], rdx
        .execNotPhdrHost:

        movzx rax, word [ehdr.phentsize]            ; matches sizeof.PHDR exactly since that was already enforced by the layout check above
        add rbx, rax
        dec rcx
        jmp .scanExecLoop
    .scanExecDone:
    ; The trampoline walks the section headers for IRELATIVE fixups, so that
    ; table must lie inside the file too (shnum 0 means stripped, nothing to walk)
    movzx eax, word [ehdr.shnum]
    test eax, eax
    jz allocateStack
    cmp word [ehdr.shentsize], sizeof.SHDR
    jne invalidLayout
    imul rax, rax, sizeof.SHDR
    add rax, [ehdr.shoff]
    jc invalidLayout
    cmp rax, [fstat.st_size]
    ja invalidLayout
    jmp allocateStack

; ET_DYN pre scan.
; PIE can move, so before mapping anything we figure out the whole PT_LOAD
; span, reserve a window for it, and then map into it
scanDynImage:
    mov [baseAddr], 0
    mov qword [phdrRuntime], 0
    mov byte [hasInterp], 0
    mov byte [hasDynamic], 0
    mov byte [hasTls], 0
    mov byte [stackProt], PROT_READ or PROT_WRITE
    mov qword [dynamicVaddr], 0
    mov qword [dynamicSize], 0                      ; PT_DYNAMIC handling isn't wired up in this scan yet, these fields exist for whatever reads them downstream
    mov qword [tlsVaddr], 0                         ; ET_DYN's TLS vaddr is bias relative, filled in only if a PT_TLS phdr turns up below
    mov qword [tlsFilesz], 0
    mov qword [tlsMemsz], 0
    mov qword [tlsAlign], 0
    mov qword [imageMinVaddr], -1
    mov qword [imageMaxVaddr], 0                    ; 0 is a safe starting low bound, any vaddr will end up higher once the scan runs

    ; Walk the on disk phdr table straight out of the staged file image.
    lea rbx, [buffer]
    add rbx, [ehdr.phoff]                           ; same on disk phdr walk as the ET_EXEC path above, just building a span instead of hunting for TLS/interp here
    xor ecx, ecx
    movzx ecx, word [ehdr.phnum]
    .scanDynLoop:
        test rcx, rcx
        jz .scanDynDone
        ; Copy one phdr into scratch so the rest of the code can talk in named
        ; fields instead of offsets
        mov rsi, rbx
        lea rdi, [phdr]
        push rcx
        mov ecx, sizeof.PHDR                         ; again borrowing ecx for rep movsb's count, the loop counter is saved around it
        rep movsb
        pop rcx

        ; Only PT_LOAD matters for the reservation window.
        cmp dword [phdr.type], PT_LOAD
        jne .scanDynNext
        cmp qword [phdr.memsz], 0
        je .scanDynNext                                     ; a PT_LOAD with memsz 0 reserves nothing and would corrupt the min/max span if it were let through

        ; Convert the segment's virtual range into a full page rounded mapping
        ; range. mmap/mprotect operate on whole pages, so the reservation
        ; must cover the rounded start and rounded end, not just raw p_vaddr
        mov rax, [phdr.vaddr]
        and rax, -PAGE_SIZE                             ; rounds the segment start down to a whole page, mmap/mprotect can't work with anything finer
        mov rdx, [phdr.vaddr]
        add rdx, [phdr.memsz]
        add rdx, PAGE_SIZE - 1                              ; classic round up before the mask, mirrors the round down done to rax above
        and rdx, -PAGE_SIZE

        ; Merge this page rounded PT_LOAD range into the running min/max span
        ; for the eventual ET_DYN reservation window
        UPDATE_LOAD_SPAN rax, rdx, imageMinVaddr, imageMaxVaddr
        .scanDynNext:
        movzx rax, word [ehdr.phentsize]                        ; stride again matches sizeof.PHDR thanks to the earlier layout check
        add rbx, rax
        dec rcx
        jmp .scanDynLoop
    .scanDynDone:
    ; A valid ET_DYN loadable image must contain at least one PT_LOAD span.
    ; If imageMinVaddr is still -1, the scan never saw one
    mov rax, [imageMinVaddr]
    cmp rax, -1
    je invalidElf

    ; The reservation size is:
    ;   highest_page_rounded_end - lowest_page_rounded_start
    ;
    ; This gives the full adjacent VA window needed before
    ; deriving the load bias and mapping individual PT_LOAD segments into it
    mov rdx, [imageMaxVaddr]
    sub rdx, rax
    mov [imageSpanSize], rdx
    jmp getDynAddr

; Reserve an address window large enough for the whole PT_LOAD span.
; The chosen load bias is:
;   reserved_base - lowest_load_vaddr
getDynAddr:
    lea rsi, [dbgReserveDynMsg]
    mov rdx, dbgReserveDynMsgLen
    call debugWrite
    xor rdi, rdi
    mov rsi, [imageSpanSize]
    mov rdx, PROT_READ or PROT_WRITE
    mov r10, MAP_PRIVATE or MAP_ANON
    mov r8, -1                                              ; no fd backs this reservation
    xor r9, r9
    mov rax, SYS_MMAP
    syscall
    test rax, rax
    js mmapFailed
    mov rdx, [imageMinVaddr]
    sub rax, rdx                                            ; bias = reserved base - lowest vaddr, gets added to every phdr.vaddr later when segments are actually mapped
    mov qword [baseAddr], rax
    lea rsi, [dbgLoadBiasMsg]
    mov rdx, dbgLoadBiasMsgLen
    mov rax, [baseAddr]
    call debugPrintHexLine
