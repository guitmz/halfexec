fstat       STAT    ; stat() result for the main target file
ehdr        EHDR    ; scratch ELF header for the main image
phdr        PHDR    ; scratch phdr reused while walking phdr tables
interpStat  STAT    ; stat() result for PT_INTERP
interpEhdr  EHDR    ; scratch ELF header for PT_INTERP

targetFd        rq 1    ; main target fd for pread/read
interpFd        rq 1    ; interpreter fd while loadInterp is doing its thing
exitStatus      rb 1    ; final status byte returned to the shell
hasInterp       rb 1    
hasDynamic      rb 1    
hasTls          rb 1    
debugEnabled    rb 1    ; set by HALFEXEC_DEBUG during startup

targetArgc          rq 1    
targetArgv          rq 1    
targetEnvp          rq 1    
targetEnvc          rq 1    
targetAuxv          rq 1    
targetAuxc          rq 1    
targetPath          rq 1    
targetPathNew       rq 1    ; copied pathname pointer inside the rebuilt stack
newStackPtr         rq 1    
argvDst             rq 1    
envpDst             rq 1    
auxvDst             rq 1    
stringWritePtr      rq 1    ; upwards growing cursor for copied strings and aux blobs
totalStringBytes    rq 1    ; total bytes needed for copied argv/env strings

stackAddr       rq 1    ; base address of the custom stack
baseAddr        rq 1    ; main image load bias (zero for ET_EXEC, non zero for ET_DYN)
interpBaseAddr  rq 1    
phdrRuntime     rq 1    ; runtime AT_PHDR pointer if a PT_LOAD hosts the phdr table
interpPathPtr   rq 1    ; pointer into the staged main ELF where PT_INTERP is

dynamicVaddr    rq 1    ; PT_DYNAMIC inside the mapped main image
dynamicSize     rq 1    ; PT_DYNAMIC from the phdr
tlsVaddr        rq 1    ; PT_TLS virtual address for ET_DYN copies
tlsOffset       rq 1    ; PT_TLS file offset for ET_EXEC pre remap copies
tlsFilesz       rq 1    ; file TLS byte count
tlsMemsz        rq 1    ; total TLS size after zeroying
tlsAlign        rq 1    ; raw PT_TLS alignment request
tlsAlignWork    rq 1    ; normalized TLS alignment after cleanup
tlsBlock        rq 1    ; base of the actual TLS data block
tlsTcb          rq 1    ; FS base/synthetic TCB address

relaAddr    rq 1    ; DT_RELA for the main relocation table
relaSize    rq 1    ; DT_RELASZ for the main relocation table
relaEnt     rq 1    ; DT_RELAENT size of one RELA record
jmprelAddr  rq 1    ; DT_JMPREL for the PLT/JMPREL relocation table
jmprelSize  rq 1    ; DT_PLTRELSZ for the PLT/JMPREL table
pltrelType  rq 1    ; DT_PLTREL encoding tag, expected to be DT_RELA

imageMinVaddr       rq 1    ; lowest rounded PT_LOAD address in the main ET_DYN image
imageMaxVaddr       rq 1    ; highest rounded PT_LOAD end in the main ET_DYN image
imageSpanSize       rq 1    ; full main image PT_LOAD span reserved before mapping
interpImageMinVaddr rq 1    ; lowest rounded PT_LOAD address in the interpreter
interpImageMaxVaddr rq 1    ; highest rounded PT_LOAD end in the interpreter
interpImageSpanSize rq 1    ; full interpreter PT_LOAD span reserved before mapping

waitStatus  rd 1    ; raw wait4 status from the ET_EXEC child
scratchAddr rq 1    ; base of the child scratch reservation
scratchCode rq 1    ; address of the copied trampoline inside scratch
scratchFile rq 1    ; address of the copied ET_EXEC file image inside scratch

stackProt       db PROT_READ or PROT_WRITE  ; final stack protection mask
debugHexBuf     rb 19                       ; scratch buffer for "0x" + 16 hex digits + "\n"
buffer          rb BUFFER_SIZE              ; staging buffer for the main target ELF
interpBuffer    rb BUFFER_SIZE              ; staging buffer for PT_INTERP
