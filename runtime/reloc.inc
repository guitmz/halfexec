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
        cmp rax, DT_RELACOUNT                               ; tells you how many leading RELA entries are RELATIVE, unused since every entry gets scanned anyway
        jne .nextDynamic
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
    je .applyRelaRelative
    cmp qword [pltrelType], DT_RELA                         ; DT_REL (no addend field) would need a different loop entirely, not supported
    jne unsupportedReloc

    ; Pass 1: plain RELATIVE relocations.
    ; write (base + addend) into (base + offset) and contune. Do this first so
    ; later we proces against a simpler image
    .applyRelaRelative:
    mov rsi, [baseAddr]
    add rsi, [relaAddr]                                     ; relaAddr is a vaddr from DT_RELA, needs the same base offset as any other pointer into the image
    mov rcx, [relaSize]                                     ; the RELA table's byte length, as read from DT_RELASZ above
    xor rdx, rdx
    mov rax, [relaEnt]
    test rax, rax                                           ; guards the div below, a zero relaEnt would fault instead of failing cleanly
    jz unsupportedReloc
    div rax                                                 ; turns the byte size into an entry count
    mov rcx, rax
    .relaRelativeLoop:
        test rcx, rcx
        jz .applyJmpRelRelative
        mov rax, [rsi + RELA.info]
        and eax, 0xffffffff                                ; low bits hold the relocation type
        cmp eax, R_X86_64_RELATIVE                          ; other relocation types aren't rejected until pass 2, this pass only ever touches RELATIVE ones
        jne .nextRelaRelative
        mov rdi, [baseAddr]
        add rdi, [rsi + RELA.offset]                        ; offset is the address, relative to the image, of the pointer slot being fixed up
        mov rax, [baseAddr]
        add rax, [rsi + RELA.addend]                        ; addend is the value the linker recorded, itself relative to the image's own base
        mov [rdi], rax
        .nextRelaRelative:
        add rsi, sizeof.RELA
        dec rcx
        jmp .relaRelativeLoop

    .applyJmpRelRelative:
    ; Some static PIEs also sneak RELATIVE relocations into JMPREL
    cmp qword [jmprelSize], 0
    je .applyRelaIRelative
    mov rsi, [baseAddr]
    add rsi, [jmprelAddr]                                   ; same walk as the RELA pass above, just over the PLT relocation table
    mov rcx, [jmprelSize]                                   ; JMPREL table's byte length, from DT_PLTRELSZ above
    xor rdx, rdx
    mov rax, [relaEnt]
    test rax, rax
    jz unsupportedReloc                                     ; same div by zero guard as the RELA pass
    div rax
    mov rcx, rax
    .jmprelRelativeLoop:
        test rcx, rcx
        jz .applyRelaIRelative
        mov rax, [rsi + RELA.info]
        and eax, 0xffffffff                                 ; same relocation type mask as above
        cmp eax, R_X86_64_RELATIVE                          ; same selective pass, unsupported types get caught later against IRELATIVE
        jne .nextJmpRelRelative
        mov rdi, [baseAddr]
        add rdi, [rsi + RELA.offset]
        mov rax, [baseAddr]
        add rax, [rsi + RELA.addend]
        mov [rdi], rax
        .nextJmpRelRelative:
        add rsi, sizeof.RELA
        dec rcx
        jmp .jmprelRelativeLoop

    .applyRelaIRelative:
    ; Pass 2: IRELATIVE relocations.
    ; These call back into resolver code inside the image, after the plain
    ; RELATIVE pointers are already fixed
    mov rsi, [baseAddr]
    add rsi, [relaAddr]                                     ; identical entry count math as pass 1, now scanning for IRELATIVE instead of RELATIVE
    mov rcx, [relaSize]
    xor rdx, rdx
    mov rax, [relaEnt]
    test rax, rax
    jz unsupportedReloc
    div rax                                                 ; same byte size to entry count conversion as pass 1
    mov rcx, rax
    .relaIRelativeLoop:
        test rcx, rcx
        jz .applyJmpRelIRelative
        mov rax, [rsi + RELA.info]
        and eax, 0xffffffff                                 ; low bits hold the relocation type, same mask as pass 1
        cmp eax, R_X86_64_IRELATIVE
        jne .checkUnsupportedRela                           ; anything that isn't RELATIVE or IRELATIVE finally gets rejected here
        mov rdi, [baseAddr]
        add rdi, [rsi + RELA.offset]                        ; still the slot being fixed up, but the value that lands here comes from calling code below
        mov rax, [baseAddr]
        add rax, [rsi + RELA.addend]                        ; for IRELATIVE, addend is the resolver function's address, not the final value
        push rcx                                            ; loop state has to survive the call, the resolver is arbitrary code and its calling convention isn't ours to assume
        push rsi
        push rdi
        call rax                                            ; jumps into the image's own ifunc resolver to get the real pointer value
        pop rdi
        pop rsi
        pop rcx
        mov [rdi], rax                                      ; rax on return is the resolved pointer, that's what actually goes into the relocation slot
        jmp .nextRelaIRelative
        .checkUnsupportedRela:
        cmp eax, R_X86_64_RELATIVE                          ; RELATIVE entries were already handled in pass 1, seeing one again here is fine
        je .nextRelaIRelative
        jmp unsupportedReloc
        .nextRelaIRelative:
        add rsi, sizeof.RELA
        dec rcx
        jmp .relaIRelativeLoop

    .applyJmpRelIRelative:
    ; Same idea again for the PLT relocation table, because some binaries stash
    ; IRELATIVE entries there instead of in the main RELA table (if I understood
    ; correctly, but seems to work?)
    cmp qword [jmprelSize], 0
    je prepareTlsAndStack
    mov rsi, [baseAddr]
    add rsi, [jmprelAddr]                                   ; same JMPREL walk as the RELATIVE pass above, this time hunting IRELATIVE entries
    mov rcx, [jmprelSize]
    xor rdx, rdx
    mov rax, [relaEnt]
    test rax, rax
    jz unsupportedReloc                                     ; same guard against a zero relaEnt as the earlier passes
    div rax                                                 ; same conversion once more, over the PLT table
    mov rcx, rax
    .jmprelIRelativeLoop:
        test rcx, rcx
        jz prepareTlsAndStack                               ; ran out of JMPREL entries, both relocation passes are done, safe to continue booting the target
        mov rax, [rsi + RELA.info]
        and eax, 0xffffffff                                 ; relocation type mask, same as the other three passes
        cmp eax, R_X86_64_IRELATIVE
        jne .checkUnsupportedJmpRel
        mov rdi, [baseAddr]
        add rdi, [rsi + RELA.offset]                        ; same slot-plus-call situation as the RELA IRELATIVE pass above
        mov rax, [baseAddr]
        add rax, [rsi + RELA.addend]                        ; addend here is again a resolver address, not a plain pointer value
        push rcx
        push rsi
        push rdi
        call rax                                            ; PLT variant of the same ifunc resolver call
        pop rdi
        pop rsi
        pop rcx
        mov [rdi], rax                                      ; store the resolver's actual return value, mirroring the RELA IRELATIVE pass
        jmp .nextJmpRelIRelative
        .checkUnsupportedJmpRel:
        cmp eax, R_X86_64_RELATIVE
        je .nextJmpRelIRelative
        jmp unsupportedReloc
        .nextJmpRelIRelative:
        add rsi, sizeof.RELA
        dec rcx
        jmp .jmprelIRelativeLoop
