format ELF64 executable 3

include "utils.inc"
;   1. read and validate the target ELF
;   2. map the main image
;   3. optionally load PT_INTERP
;   4. rebuild the initial process stack
;   5. jump directly or via the ET_EXEC child trampoline
segment readable executable
entry $
; Parse the loader's own initial stack
;
; Linux starts us with:
;   [rsp + 0]  = argc
;   [rsp + 8]  = argv[0]
;   [rsp + 16] = argv[1]
;
; halfexec wants one target path, and later it rebuilds the target argv so its 
; argv[0] becomes the path received as argv[1]
    mov rcx, [rsp]                                               ; this is our own initial stack from the kernel, the target gets a rebuilt one later
    cmp rcx, 2
    jl usage                                                     ; argc counts our own program name too, so 2 means a name plus one target path
    mov rax, rcx
    dec rax                                                      ; target argc is one less than ours, since its argv[0] becomes this argv[1]
    mov [targetArgc], rax
    lea rax, [rsp + 16]                                          ; argv[1] onward becomes the whole target argv array
    mov [targetArgv], rax
    mov rax, [rsp + 16]                                          ; grabbed again since open() below wants the path value, not the array address
    mov [targetPath], rax
; Scan envp once and set debug check byte accordingly. A bit hacky I suppose
; but we are here already so might as well
; Doing this scan before opening the target means every step after this
; point, including the open/fstat/mmap calls below, can already report
; through debugWrite the moment HALFEXEC_DEBUG flips the flag on.
    mov byte [debugEnabled], 0
    lea rbx, [rsp + rcx * 8 + 16]                                ; steps over argc, the rcx argv pointers, and argv's own NULL to land on envp[0]
    ; Only the first HALFEXEC_DEBUG= entry found counts. A match jumps
    ; straight to .done_debug_env, so a second later entry is never reached.
    .find_debug_env:
        mov rdi, [rbx]                                           ; no libc here, so matching HALFEXEC_DEBUG= is a hand rolled byte compare
        test rdi, rdi
        jz .done_debug_env                                       ; a NULL pointer marks the end of envp
        lea rsi, [debugEnvPrefix]
        mov rdx, debugEnvPrefixLen                               ; length includes the '=', so a similarly prefixed but different var name will not match
        .loop_env:
            test rdx, rdx
            jz .found_debug_env
            mov al, [rdi]
            mov cl, [rsi]
            cmp al, cl                                           ; case sensitive, HALFEXEC_DEBUG lowercase would not be recognized
            jne .next_env
            inc rdi
            inc rsi
            dec rdx
            jmp .loop_env
        .found_debug_env:
            ; empty or zero means off. Anything else, means on
            mov al, [rdi]
            test al, al
            jz .next_env
            cmp al, '0'
            je .next_env
            mov byte [debugEnabled], 1
            lea rsi, [versionMsg]                                ; print the version first so debug output has a banner instead of starting mid stream
            mov rdx, versionMsgLen
            call debugWrite
            lea rsi, [dbgEnabledMsg]
            mov rdx, dbgEnabledMsgLen
            call debugWrite
            jmp .done_debug_env
        .next_env:
        add rbx, 8                                               ; envp entries are plain pointers, 8 bytes apart on x64
        jmp .find_debug_env
    .done_debug_env:
; Open the target file for reading
    mov rdi, [targetPath]                                              ; same pointer stashed above, now handed to open()
    mov rsi, O_RDONLY
    xor rdx, rdx
    mov rax, SYS_OPEN
    syscall
    test rax, rax
    js openFailed
    mov [targetFd], rax
; Get the target file size for bounds checks and to know how many bytes to use
    mov rdi, [targetFd]
    lea rsi, [fstat]
    mov rax, SYS_FSTAT
    syscall
    test rax, rax
    js fstatFailed
; Put the entire target file in memory. The PT_LOAD mapping code copies segment
; bytes out of this buffer into the final mappings
    cmp qword [fstat.st_size], BUFFER_SIZE                                              ; BUFFER_SIZE is a fixed 1 mb arena, anything larger cannot be staged at all
    jg fileTooLarge
    mov rdi, [targetFd]
    lea rsi, [buffer]
	    mov rdx, [fstat.st_size]
	    mov rax, SYS_READ
	    syscall
	    cmp rax, [fstat.st_size] ; a short read here would leave buffer only partially populated
	    jne fileReadFailed
	; The whole file lives in buffer, but the rest of the loader talks to the
	; main ELF header through the dedicated ehdr scratch struct. Keep those two
	; views in sync before validate.inc starts reading named EHDR fields
	    lea rsi, [buffer]
	    lea rdi, [ehdr]
	    mov ecx, sizeof.EHDR
	    rep movsb
; Delay close(). The fd stays open for now because it is still used later by
; pread64() while walking the main PHDR table
include "runtime/validate.inc"
; Allocate a custom target stack mapping
;   * create the RW stack mapping that will be populate
;   * reserve enough room for argv/envp/auxv pointer tables and copied string
;     payloads
;   * do not write the final stack contents yet because it may still need to
;     patch auxv values based on interpreter/TLS scenarios
; STACK_SIZE is the whole reservation below. At most STACK_ARGS_LIMIT of it
; holds copied argv/envp strings and pointer tables (see stack.inc), the rest
; is normal stack growth once the target is running.
allocateStack:
    xor rdi, rdi
    mov rsi, STACK_SIZE                                          ; sized well beyond what argv/envp/auxv plus their copied strings should ever need
    movzx edx, byte [stackProt]                                  ; ET_EXEC honors PT_GNU_STACK here, ET_DYN mprotects again in processPhdrs
    mov r10, MAP_PRIVATE or MAP_ANON
    mov r8, -1
    xor r9, r9
    mov rax, SYS_MMAP
    syscall
    test rax, rax
    js mmapFailed
    mov qword [stackAddr], rax
    lea rsi, [dbgStackMsg]
    mov rdx, dbgStackMsgLen
    mov rax, [stackAddr]
    call debugPrintHexLine
    cmp word [ehdr.type], ET_EXEC
    je execAfterStack                                            ; ET_EXEC skips the whole PHDR walk below, execPrepare already gathered what it needs
; Main image PHDR processing
;   * iterate all image phdrs from the ELF file
;   * remember PT_INTERP/PT_DYNAMIC/PT_TLS/PT_GNU_STACK metadata
;   * map each PT_LOAD segment RW, populate it, zero bss, then mprotect it to
;     the final PF_* permissions
;   * compute phdrRuntime for AT_PHDR if the phdr table is inside a PT_LOAD
;     segment
; Only reached for ET_DYN targets. ET_EXEC already branched to execAfterStack
; above, since its own PHDR table was pre scanned by execPrepare in
; validate.inc and none of it needs remapping before the fork/trampoline
; dance later on. baseAddr here is the non zero load bias getDynAddr picked,
; not the zero bias an ET_EXEC image uses.
;
; This is actually the second time PT_LOAD gets walked for an ET_DYN target.
; scanDynImage already walked it once just to size the reservation window in
; getDynAddr. This second pass copies bytes in and sets final permissions
processPhdrs:
    mov qword [phdrRuntime], 0
    mov r9, [ehdr.phoff]                                         ; r9 walks the on disk phdr table by file offset, bx below counts which entry
    xor rbx, rbx
    .loopPhdr:
        ; Each pass reads one phdr straight from disk into the shared scratch
        ; struct below, rather than parsing it out of the buffer we already
        ; staged in memory. That is what "Delay close()" earlier bought us.
        mov rdi, [targetFd]
        lea rsi, [phdr]
        movzx edx, word [ehdr.phentsize]                         ; already validated equal to sizeof.PHDR earlier, so this always fills the struct fully
        mov r10, r9                                              ; r10 is pread64 file offset argument, avoids a separate seek to walk the table
        mov rax, SYS_PREAD64
        syscall
        cmp rax, sizeof.PHDR                                     ; a short read here would feed a partly garbage phdr into every check below
        jne phdrReadFailed
        ; PT_GNU_STACK is a modern addition to the segment table that never
        ; existed in the original ELF spec. It carries no bytes to load, only
        ; the executable stack flag GNU tooling started emitting once NX
        ; became common. We honor it so a target that needs an executable
        ; stack still gets one on our synthetic replacement.
        cmp dword [phdr.type], PT_GNU_STACK
        jne .notStack
            mov r8d, [phdr.flags]                                ; p_flags carries PF_X here, the only bit PT_GNU_STACK actually uses
            ELF_FLAGS_TO_PROT r8d, edx                           ; PF_* and PROT_* bit numbering do not line up, see the macro
            .stackProtect:
                mov [stackProt], dl
                mov rdi, [stackAddr]                             ; keep our synthetic stack matching whatever exec permission the target requested
                mov rsi, STACK_SIZE
                mov rax, SYS_MPROTECT
                syscall
                test rax, rax
                js mprotectFailed                                ; extremely unlikely, this mapping was just created by us a few lines above
        .notStack:
            cmp dword [phdr.type], PT_INTERP                     ; the dynamic linker's own path, when the target needs one
            jne .notInterp
            ; PT_INTERP must stay within the file and end in a trailing NUL
            ; byte because the later open() path uses it as a path name
            cmp qword [phdr.filesz], 0
            je invalidInterpPath
            CHECK_FILE_RANGE [phdr.offset], [phdr.filesz], [fstat.st_size], invalidInterpPath
            mov byte [hasInterp], 1
            lea rax, [buffer]
            add rax, [phdr.offset]                                ; rax now points at the interpreter path bytes inside our staged copy of the file
            mov rcx, [phdr.filesz]                                ; filesz doubles as the path's byte length here, including its terminator
            dec rcx
            cmp byte [rax + rcx], 0                               ; must be the LAST byte of the declared range, not just a zero somewhere inside it
            jne invalidInterpPath
            mov [interpPathPtr], rax                              ; points straight into buffer, so buffer has to stay alive as long as this is used
        .notInterp:
            ; PT_DYNAMIC and PT_TLS below are not acted on here at all. This pass
            ; only walks the table once, so anything a later phase needs gets
            ; copied into named globals now and read back by reloc.inc or
            ; stack.inc once the actual mapping and relocation work begins.
            ; PT_DYNAMIC points at the dynamic section driving relocations and
            ; symbol binding, PT_TLS describes the thread local template a libc
            ; needs copied per thread. Keeping processPhdrs itself limited to
            ; walk once, record facts, map PT_LOAD means all the actual
            ; relocation and TLS setup logic can live in its own include file.
            cmp dword [phdr.type], PT_DYNAMIC
            jne .notDynamic
            mov byte [hasDynamic], 1                              ; read later by reloc.inc to decide whether relocations need to run at all
            mov rax, [phdr.vaddr]                                ; p_vaddr: where the DYNAMIC table lands once this segment is mapped
            mov [dynamicVaddr], rax
            mov rax, [phdr.memsz]                                ; p_memsz here is just the DYNAMIC table's byte span
            mov [dynamicSize], rax
        .notDynamic:
            cmp dword [phdr.type], PT_TLS
            jne .notTls
            mov byte [hasTls], 1                                   ; read later by stack.inc to decide whether a TCB needs to be built
            mov rax, [phdr.vaddr]                                ; PT_TLS's vaddr becomes the template address for the initial TLS block
            mov [tlsVaddr], rax
            mov rax, [phdr.filesz]                               ; bytes actually present in the file for the TLS template
            mov [tlsFilesz], rax
            mov rax, [phdr.memsz]                                ; total per thread TLS size once the zero filled tail is added
            mov [tlsMemsz], rax
            mov rax, [phdr.align]                                ; alignment the TCB placement has to respect, easy to get wrong
            mov [tlsAlign], rax
        .notTls:
            cmp dword [phdr.type], PT_LOAD                       ; the one type that actually needs a mapping, everything above was just bookkeeping
            jne .nextPhdr
            ; All bytes copied from the file must actually exist in the
            ; ELF. The loader allows bss segments (filesz == 0) but not file
            ; ranges that overrun the input buffer
            CHECK_PT_LOAD [fstat.st_size], invalidSegment
            ; AT_PHDR needs the runtime address of the phdr table itself, not
            ; just where the segments load. If this PT_LOAD's file range
            ; happens to cover ehdr.phoff, that address can be derived right
            ; here instead of hunting for it separately later
            mov rax, [ehdr.phoff]
            cmp rax, [phdr.offset]
            jb .notPhdrHost
            mov rdx, [phdr.offset]
            add rdx, [phdr.filesz]
            cmp rax, rdx
            jae .notPhdrHost
            mov rdx, [baseAddr]
            add rdx, [phdr.vaddr]
            add rdx, rax
            sub rdx, [phdr.offset]
            mov [phdrRuntime], rdx
            .notPhdrHost:
            cmp qword [phdr.memsz], 0                            ; some PT_LOAD entries carry no bytes at all and need nothing mapped
            je .nextPhdr
; Page align this PT_LOAD
; mmap and mprotect only work on whole pages, so both the start address and
; the total size have to be rounded to PAGE_SIZE boundaries before any
; syscall below can succeed
            mov r15, [phdr.vaddr]
            and r15, -PAGE_SIZE
            push r15                                             ; saved across the mmap/copy work below, needed again for mprotect at the end
            mov r14, [phdr.vaddr]
            sub r14, r15                                         ; r14 is now vaddr's offset into its own page, since the mapping starts at r15
            mov r13, [phdr.memsz]
            add r13, r14                                         ; mapping size must also cover that offset, not just memsz
            add r13, PAGE_SIZE - 1
            and r13, -PAGE_SIZE                                  ; classic round up to a page boundary: add (PAGE_SIZE - 1) then mask the low bits
            push r13                                             ; saved for the mprotect size once permissions are worked out below
; Map RW first, fill everything, then tighten permissions. Not the fanciest
; approach
           push r9                                               ; r9 is our phdr file cursor, mmap wants r9 as its own offset argument
           mov rdi, [baseAddr]
           add rdi, r15
           mov rsi, r13
           mov rdx, PROT_READ or PROT_WRITE
           mov r10, MAP_PRIVATE or MAP_ANON or MAP_FIXED         ; MAP_FIXED trusts our address math completely, a bug here overwrites us silently
           mov r8, -1
           xor r9, r9
           mov rax, SYS_MMAP
           syscall
           test rax, rax
           js mmapFailed                                        ; most likely means the fixed address here collides with something already mapped
           pop r9
           lea rsi, [dbgMapMainMsg]
           mov rdx, dbgMapMainMsgLen
           mov rax, [baseAddr]
           add rax, r15
           call debugPrintHexLine
; Copy the file part straight out of the staged ELF image
           mov r10, [phdr.offset]
           mov r11, [phdr.vaddr]
           lea rsi, [buffer + r10]                               ; buffer already holds the whole file, so segment bytes come straight out of it
           mov rdi, [baseAddr]
           add rdi, r11                                          ; destination is the segment's real runtime address, baseAddr is the ET_DYN load bias
           mov rcx, [phdr.filesz]
           .memcpy:
               test rcx, rcx                                    ; guards filesz == 0, loop decrements before testing so a zero count would wrap around
               jz .memcpy_done
               lodsb
               stosb
               loop .memcpy
           .memcpy_done:
; if memsz > filesz, the difference is just bss and needs to be zeroed
           mov r10, [phdr.memsz]
           mov r11, [phdr.filesz]
           cmp r10, r11
           jl .bssIgnore                                        ; memsz < filesz was already rejected above, this is really just the equal case
           sub r10, r11
           mov rcx, r10
           mov r10, [phdr.vaddr]                                 ; r10 switches meaning here, from a byte count to the segment's base address
           mov rdi, [baseAddr]
           add rdi, r10
           add rdi, r11                                          ; rdi now points right after the copied file bytes, where bss begins
           mov al, 0
           rep stosb
; Set the segment permissions it needs so much
           .bssIgnore:
               mov r8d, [phdr.flags]
               ELF_FLAGS_TO_PROT r8d, edx                        ; same conversion as the stack case above, now for this segment's own PF_* bits
               .phdrProtect:
                   pop r13                                       ; restoring the page rounded size and base saved before the mmap/copy work above
                   pop r15
                   mov rdi, [baseAddr]
                   add rdi, r15
                   mov rsi, r13
                   mov rax, SYS_MPROTECT
                   syscall
                   test rax, rax
                   js mprotectFailed                             ; would mean the flags translation above produced something the kernel rejects
; Keep going until we run out of phdrs
    .nextPhdr:
        inc bx
        cmp bx, word [ehdr.phnum]                                ; ehdr.phnum caps how many entries to walk, straight from the file header
        jge interp
        movzx r10, word [ehdr.phentsize]
        add r9, r10                                              ; keeps r9 in sync with bx, advancing by exactly one phdr entry each pass
        jmp .loopPhdr
; From here, two options:
;   * load the PT_INTERP image and hand control to it
;   * apply the main image relocations and jump directly
; execAfterStack is the ET_EXEC entry into this decision process. interp is
; the ET_DYN entry after the main image has already been mapped
execAfterStack:
    cmp byte [hasInterp], 0                                      ; hasInterp was set either by execPrepare for ET_EXEC or by processPhdrs for ET_DYN
    jne loadInterp
    jmp prepareTlsAndStack

include "runtime/reloc.inc"
include "runtime/interp.inc"
include "runtime/stack.inc"
; ET_EXEC is the reaaaaaally annoying one. This is heavily commented because
; it was a big pain to get right so I took no chances
; Fixed mappings can stomp on the loader, so the trick is:
;   * parent stays behind and waits
;   * child goes into scratch memory first
;   * scratch code remaps the target where it wants to live
forkTransformExec:
    ; The parent gets to be boring and supervisory but child gets to be messy.
    ; But the child gets the hard job here...
    lea rsi, [dbgForkMsg]
    mov rdx, dbgForkMsgLen
    call debugWrite
    mov rax, SYS_FORK
    syscall
    test rax, rax
    js forkFailed
    test rax, rax                                 ; zero means we are now executing in the child process
    jz .child
    mov rdi, rax
    lea rsi, [waitStatus]
    xor rdx, rdx
    xor r10, r10
    mov rax, SYS_WAIT4
    syscall
    test rax, rax
    js waitFailed
    mov eax, [waitStatus]
    mov ecx, eax
    and ecx, 0x7f                                 ; low 7 bits hold the terminating signal number when signaled
    jnz .signaled
    shr eax, 8                                    ; normal exits encode the exit code in the high byte (y tho)
    mov [exitStatus], al
    jmp exit
    .signaled:
    add ecx, 128                                  ; shell convention baby! signaled processes usually report 128 + signal
    mov [exitStatus], cl
    jmp exit
    .child:
    ; Scratch mapping layout:
    ;   [EXEC_CTX][trampoline code][padding][staged ELF file image]
    ; The trampoline runs entirely from this high scratch area while it remaps
    ; the ET_EXEC PT_LOAD segments to their final fixed virtual addresses
    mov rax, [fstat.st_size]
    add rax, sizeof.EXEC_CTX + execTrampolineSize + 64
    add rax, PAGE_SIZE - 1
    and rax, -PAGE_SIZE
    xor rdi, rdi
    mov rsi, rax
    mov rdx, PROT_READ or PROT_WRITE or PROT_EXEC ; scratch area must be executable because it holds the trampoline code
    mov r10, MAP_PRIVATE or MAP_ANON
    mov r8, -1
    xor r9, r9
    mov rax, SYS_MMAP
    syscall
    test rax, rax
    js .childFail
    mov [scratchAddr], rax
    lea r12, [rax + sizeof.EXEC_CTX]
    mov [scratchCode], r12
    lea rsi, [execTrampolineStart]
    mov rdi, r12
    mov rcx, execTrampolineSize
    rep movsb
    mov r13, [scratchCode]
    add r13, execTrampolineSize
    add r13, 15                                   ; align the copied file to 16 bytes
    and r13, -16
    mov [scratchFile], r13
    lea rsi, [buffer]
    mov rdi, r13
    mov rcx, [fstat.st_size]
    rep movsb
    ; fill in EXEC_CTX so the trampoline in scratch memory has everything it needs
    mov rdi, [scratchAddr]
    mov rax, [scratchFile]
    mov [rdi + EXEC_CTX.file_ptr], rax
    mov rax, [fstat.st_size]
    mov [rdi + EXEC_CTX.file_size], rax
    mov rax, [ehdr.phoff]
    mov [rdi + EXEC_CTX.phoff], rax
    movzx rax, word [ehdr.phentsize]
    mov [rdi + EXEC_CTX.phentsize], rax
    movzx rax, word [ehdr.phnum]
    mov [rdi + EXEC_CTX.phnum], rax
    mov rax, [ehdr.shoff]
    mov [rdi + EXEC_CTX.shoff], rax
    movzx rax, word [ehdr.shentsize]
    mov [rdi + EXEC_CTX.shentsize], rax
    movzx rax, word [ehdr.shnum]
    mov [rdi + EXEC_CTX.shnum], rax
    mov rax, [ehdr.entry]
    mov [rdi + EXEC_CTX.entry], rax
    mov rax, [newStackPtr]
    mov [rdi + EXEC_CTX.stack_ptr], rax
    movzx rax, byte [hasInterp]
    mov [rdi + EXEC_CTX.has_interp], rax
    mov rax, [interpEhdr.entry]
    add rax, [interpBaseAddr]
    mov [rdi + EXEC_CTX.interp_entry], rax
    mov rdi, [scratchAddr]                        ; rdi carries EXEC_CTX into the trampoline
    mov rax, [scratchCode]
    jmp rax
    .childFail:
    mov edi, 1
    mov eax, SYS_EXIT
    syscall
; Error helpers. I started with a single generic error for everything but it 
; meant opening a debugger and stepping through the code to find where it was
; crashing. This took me a moment to write but saved me hours later
unsupportedType:
    lea rsi, [unsupportedTypeMsg]
    mov rdx, unsupportedTypeMsgLen
    jmp writeError

unsupportedInterp:
    lea rsi, [unsupportedInterpMsg]
    mov rdx, unsupportedInterpMsgLen
    jmp writeError

unsupportedReloc:
    lea rsi, [unsupportedRelocMsg]
    mov rdx, unsupportedRelocMsgLen
    jmp writeError

stackStorageTooSmall:
    lea rsi, [stackStorageTooSmallMsg]
    mov rdx, stackStorageTooSmallMsgLen
    jmp writeError

openFailed:
    lea rsi, [openFailedMsg]
    mov rdx, openFailedMsgLen
    jmp writeError

fstatFailed:
    lea rsi, [fstatFailedMsg]
    mov rdx, fstatFailedMsgLen
    jmp writeError

headerReadFailed:
    lea rsi, [headerReadFailedMsg]
    mov rdx, headerReadFailedMsgLen
    jmp writeError

fileTooLarge:
    lea rsi, [fileTooLargeMsg]
    mov rdx, fileTooLargeMsgLen
    jmp writeError

fileReadFailed:
    lea rsi, [fileReadFailedMsg]
    mov rdx, fileReadFailedMsgLen
    jmp writeError

closeFailed:
    lea rsi, [closeFailedMsg]
    mov rdx, closeFailedMsgLen
    jmp writeError

mmapFailed:
    lea rsi, [mmapFailedMsg]
    mov rdx, mmapFailedMsgLen
    jmp writeError

phdrReadFailed:
    lea rsi, [phdrReadFailedMsg]
    mov rdx, phdrReadFailedMsgLen
    jmp writeError

mprotectFailed:
    lea rsi, [mprotectFailedMsg]
    mov rdx, mprotectFailedMsgLen
    jmp writeError

archPrctlFailed:
    lea rsi, [archPrctlFailedMsg]
    mov rdx, archPrctlFailedMsgLen
    jmp writeError

forkFailed:
    lea rsi, [forkFailedMsg]
    mov rdx, forkFailedMsgLen
    jmp writeError

waitFailed:
    lea rsi, [waitFailedMsg]
    mov rdx, waitFailedMsgLen
    jmp writeError

writeError:
    mov rdi, STDERR                                              
    mov rax, SYS_WRITE
    syscall
    mov [exitStatus], 1
    jmp exit
; Debug helpers
; No libc means no fprintf to lean on, so every trace message in this file
; funnels through one of these two instead of hand rolling a write() syscall
; at each call site
debugWrite:
    cmp byte [debugEnabled], 0                                   ; so this can be sprinkled everywhere without worrying about cost when tracing is off
    je .done
    push rax
    push rdi
    push rcx
    push r11                                                     ; syscall itself clobbers rcx and r11, so these need saving even unasked
    mov rdi, STDERR
    mov rax, SYS_WRITE
    syscall
    pop r11
    pop rcx
    pop rdi
    pop rax
    .done:
    ret
; Inputs:
;   rsi = prefix string
;   rdx = prefix length
;   rax = 64bit value
; Output:
;   <prefix>0xhhhhhhhhhhhhhhhh\n
; It preserves the registers the surrounding loader code should care about
; so it can be dropped into the hot path without forcing the call site to
; become tangled
debugPrintHexLine:
    cmp byte [debugEnabled], 0
    je .done
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r11                                                     ; syscall clobbers rcx and r11 itself, on top of whatever this call needs kept safe

    mov rdi, STDERR
    mov rax, SYS_WRITE
    syscall

    pop r11
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    push rax                                                     ; rax (the value to print) survived the restore above, saved again for the second write
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r11

    lea rdi, [debugHexBuf]
    mov byte [rdi], '0'
    mov byte [rdi + 1], 'x'
    lea rsi, [hexDigits]
    mov rbx, rax
    lea rdi, [debugHexBuf + 2]
    mov rcx, 16                                                  ; 16 hex digits needed to print a full 64bit value
    .hexLoop:
        mov r8, rbx
        shr r8, 60                                               ; pulls out the top nibble each pass, shl below feeds the next one up next time
        mov dl, [rsi + r8]
        mov [rdi], dl
        inc rdi
        shl rbx, 4
        dec rcx
        jnz .hexLoop
    mov byte [rdi], 10
    mov rdi, STDERR
    lea rsi, [debugHexBuf]
    mov rdx, 19
    mov rax, SYS_WRITE
    syscall

    pop r11
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    .done:
    ret
; Early argument and validation failures
usage:
    lea rsi, [versionMsg]
    mov rdx, versionMsgLen
    mov rdi, STDOUT                                              ; usage output goes to stdout, not stderr, since it is not always an error condition
    mov rax, SYS_WRITE
    syscall
    lea rsi, [usageMsg]
    mov rdx, usageMsgLen
    mov rdi, STDOUT
    mov rax, SYS_WRITE
    syscall
    mov [exitStatus], 1
    jmp exit

invalidElf:
    lea rsi, [invalidElfMsg]
    mov rdx, invalidElfMsgLen
    jmp writeError

invalidLayout:
    lea rsi, [invalidLayoutMsg]
    mov rdx, invalidLayoutMsgLen
    jmp writeError

invalidSegment:
    lea rsi, [invalidSegmentMsg]
    mov rdx, invalidSegmentMsgLen
    jmp writeError

invalidInterpPath:
    lea rsi, [invalidInterpPathMsg]
    mov rdx, invalidInterpPathMsgLen
    jmp writeError

invalidArch:
    lea rsi, [invalidArchMsg]
    mov rdx, invalidArchMsgLen
    jmp writeError
; Arrivederci!
exit:
    mov dil, byte [exitStatus]                    
    mov rax, SYS_EXIT                             
    syscall
include "runtime/trampoline.inc"

segment readable
include "runtime/rodata.inc"

segment readable writeable
include "runtime/rwdata.inc"
