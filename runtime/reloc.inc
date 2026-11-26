; Direct entry relocation handling for ET_DYN. It just knows specific kinds of
; relocations that we actually need and nothing else
interp:
    cmp byte [hasInterp], 0                                 ; PT_INTERP takes over the whole flow if present, plain relocation isn't needed on its own
    jne loadInterp
    cmp byte [hasDynamic], 0                                ; no PT_DYNAMIC means a static non PIE binary, there's nothing dynamic to relocate
    je prepareTlsAndStack
    lea rsi, [dbgRelocMsg]
    mov rdx, dbgRelocMsgLen
    call debugWrite                                         ; gated behind HALFEXEC_DEBUG at runtime, negligible cost when unset
    ; Read PT_DYNAMIC once to find the RELA/JMPREL tables and their sizes.
    ; If the target wants more than RELATIVE/IRELATIVE world, let's bail
    mov rsi, [baseAddr]                                     ; baseAddr is the runtime load bias computed earlier for this ET_DYN image
    add rsi, [dynamicVaddr]                                 ; dynamicVaddr is still a link time value here, needs the runtime base added like any other pointer into the image
    mov rcx, [dynamicSize]                                  ; total byte length of the PT_DYNAMIC segment, not an entry count yet
    shr rcx, 4 ; a DYN entry is 16 bytes so this gives a count
    .parseDynamic:
        test rcx, rcx
        jz .dynamicParsed
        mov rax, [rsi + DYN.tag]                            ; tag says which DT_* entry this is, val's meaning depends entirely on it
        mov rdx, [rsi + DYN.val]                            ; val's meaning is polymorphic, here it's usually an address or a byte count depending on tag
        cmp rax, DT_NULL                                 ; terminates the array regardless of dynamicSize, some linkers pad the table with extra room
        je .dynamicParsed
        cmp rax, DT_RELA
        jne .notDtRela
        mov [relaAddr], rdx                                 ; still a link time vaddr, gets the runtime base added wherever it's actually walked below
        jmp .nextDynamic
        .notDtRela:
        cmp rax, DT_RELASZ
        jne .notDtRelaSz
        mov [relaSize], rdx                                 ; byte length of the RELA table, divided by relaEnt later to get an entry count
        jmp .nextDynamic
        .notDtRelaSz:
        cmp rax, DT_RELAENT
        jne .notDtRelaEnt
        mov [relaEnt], rdx                                ; entry size, checked against sizeof.RELA further down rather than assumed
        jmp .nextDynamic
        .notDtRelaEnt:
        cmp rax, DT_JMPREL
        jne .notDtJmpRel
        mov [jmprelAddr], rdx                            ; the PLT's own relocation table, can carry RELATIVE or IRELATIVE entries just like RELA
        jmp .nextDynamic
        .notDtJmpRel:
        cmp rax, DT_PLTRELSZ
        jne .notDtPltRelSz
        mov [jmprelSize], rdx                               ; byte length of JMPREL, same entry count math applies as for RELA
        jmp .nextDynamic
        .notDtPltRelSz:
        cmp rax, DT_PLTREL
        jne .notDtPltRel
        mov [pltrelType], rdx                               ; says whether JMPREL entries are RELA or REL shaped, only RELA is supported here
        jmp .nextDynamic
        .notDtPltRel:
        .nextDynamic:
        add rsi, sizeof.DYN
        dec rcx
        jmp .parseDynamic
    .dynamicParsed:

    ; No RELA table means nothing for us to do here
    cmp qword [relaEnt], 0                                  ; staying zero means DT_RELAENT was never seen
    je prepareTlsAndStack
    cmp qword [relaEnt], sizeof.RELA                        ; mismatched entry size means a relocation layout this loader doesn't understand
    jne unsupportedReloc
    cmp qword [pltrelType], 0                               ; zero means there's no JMPREL table at all, go straight to the RELA only path
    je .applyRelocs
    cmp qword [pltrelType], DT_RELA                         ; DT_REL (no addend field) would need a different loop entirely, not supported
    jne unsupportedReloc

    .applyRelocs:
    ; Pass 1 writes every RELATIVE slot in both tables. Pass 2 runs the IRELATIVE
    ; resolvers, so they already see fixed up pointers inside the image
    mov r8d, R_X86_64_RELATIVE
    call applyRelaTables
    mov r8d, R_X86_64_IRELATIVE
    call applyRelaTables
    jmp prepareTlsAndStack

; Run one pass over both RELA and JMPREL.
; Input is r8d, the relocation type this pass applies
applyRelaTables:
    mov rsi, [relaAddr]
    mov rcx, [relaSize]
    call applyRelaTable
    mov rsi, [jmprelAddr]
    mov rcx, [jmprelSize]                                   ; some static PIEs also sneak RELATIVE/IRELATIVE entries into JMPREL
    call applyRelaTable
    ret

; Apply every entry of type r8d in one table. Any type other than RELATIVE or
; IRELATIVE is rejected, this loader does not resolve symbols.
; Inputs are rsi with the link time table vaddr, rcx with the table byte size
; and r8d with the type
applyRelaTable:
    test rcx, rcx
    jz .done
    add rsi, [baseAddr]                                     ; table vaddr needs the load bias like any other pointer into the image
    mov rax, rcx
    xor edx, edx
    div qword [relaEnt]                                     ; byte size / entry size = entry count (relaEnt was checked non zero above)
    mov rcx, rax
    .loop:
        test rcx, rcx
        jz .done
        mov eax, dword [rsi + RELA.info]                    ; low 32 bits hold the relocation type
        cmp eax, R_X86_64_RELATIVE
        je .known
        cmp eax, R_X86_64_IRELATIVE
        jne unsupportedReloc
        .known:
        cmp eax, r8d
        jne .next
        mov rdi, [baseAddr]
        add rdi, [rsi + RELA.offset]                        ; the slot being fixed up
        mov rax, [baseAddr]
        add rax, [rsi + RELA.addend]                        ; the final value for RELATIVE, the resolver address for IRELATIVE
        cmp r8d, R_X86_64_IRELATIVE
        jne .store
        ; Two calls deep plus these four pushes keeps rsp 16 byte aligned
        ; before the call, so the resolver gets the ABI entry alignment
        push rcx
        push rsi
        push rdi
        push r8
        call rax                                            ; image's own ifunc resolver returns the real pointer
        pop r8
        pop rdi
        pop rsi
        pop rcx
        .store:
        mov [rdi], rax
        .next:
        add rsi, sizeof.RELA
        dec rcx
        jmp .loop
    .done:
    ret
