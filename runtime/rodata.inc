debugEnvPrefix    db "HALFEXEC_DEBUG="
debugEnvPrefixLen = $ - debugEnvPrefix
hexDigits         db "0123456789abcdef"

dbgEnabledMsg       db "halfexec: debug tracing enabled", 10
dbgEnabledMsgLen    = $ - dbgEnabledMsg
dbgExecMsg          db "halfexec: target type ET_EXEC", 10
dbgExecMsgLen       = $ - dbgExecMsg
dbgDynMsg           db "halfexec: target type ET_DYN", 10
dbgDynMsgLen        = $ - dbgDynMsg
dbgReserveDynMsg    db "halfexec: reserving ET_DYN load window", 10
dbgReserveDynMsgLen = $ - dbgReserveDynMsg
dbgLoadBiasMsg      db "halfexec: load bias = "
dbgLoadBiasMsgLen   = $ - dbgLoadBiasMsg
dbgStackMsg         db "halfexec: synthetic stack base = "
dbgStackMsgLen      = $ - dbgStackMsg
dbgMapMainMsg       db "halfexec: mapping PT_LOAD at "
dbgMapMainMsgLen    = $ - dbgMapMainMsg
dbgInterpFoundMsg   db "halfexec: PT_INTERP found", 10
dbgInterpFoundMsgLen = $ - dbgInterpFoundMsg
dbgLoadInterpMsg    db "halfexec: loading PT_INTERP image", 10
dbgLoadInterpMsgLen = $ - dbgLoadInterpMsg
dbgInterpBaseMsg    db "halfexec: interpreter base = "
dbgInterpBaseMsgLen = $ - dbgInterpBaseMsg
dbgMapInterpMsg     db "halfexec: mapping interpreter PT_LOAD at "
dbgMapInterpMsgLen  = $ - dbgMapInterpMsg
dbgRelocMsg         db "halfexec: applying direct entry relocations", 10
dbgRelocMsgLen      = $ - dbgRelocMsg
dbgTlsMsg           db "halfexec: preparing PT_TLS runtime state", 10
dbgTlsMsgLen        = $ - dbgTlsMsg
dbgStackBuildMsg    db "halfexec: rebuilding argc/argv/envp/auxv", 10
dbgStackBuildMsgLen = $ - dbgStackBuildMsg
dbgForkMsg          db "halfexec: forking ET_EXEC child", 10
dbgForkMsgLen       = $ - dbgForkMsg
dbgJumpMainMsg      db "halfexec: jumping to main entry = "
dbgJumpMainMsgLen   = $ - dbgJumpMainMsg
dbgJumpInterpMsg    db "halfexec: jumping to interpreter entry = "
dbgJumpInterpMsgLen = $ - dbgJumpInterpMsg

versionMsg    db "halfexec v0.0.1 by TMZ (c) 2026", 10
versionMsgLen = $ - versionMsg
usageMsg      db "Usage: halfexec <path-to-elf>", 10
usageMsgLen   = $ - usageMsg

invalidElfMsg       db "halfexec: target is NOT a valid ELF64 file", 10
invalidElfMsgLen    = $ - invalidElfMsg
invalidLayoutMsg    db "halfexec: ELF header layout does NOT match the expected", 10
invalidLayoutMsgLen = $ - invalidLayoutMsg
invalidSegmentMsg   db "halfexec: a PT_LOAD file range points outside the staged ELF", 10
invalidSegmentMsgLen = $ - invalidSegmentMsg
invalidInterpPathMsg db "halfexec: PT_INTERP path is truncated or out of bounds", 10
invalidInterpPathMsgLen = $ - invalidInterpPathMsg
invalidArchMsg      db "halfexec: target is NOT ELF64", 10
invalidArchMsgLen   = $ - invalidArchMsg

unsupportedTypeMsg    db "halfexec: only ET_EXEC and ET_DYN are implemented", 10
unsupportedTypeMsgLen = $ - unsupportedTypeMsg
unsupportedInterpMsg  db "halfexec: PT_INTERP target is missing or not a supported ET_DYN image", 10
unsupportedInterpMsgLen = $ - unsupportedInterpMsg
unsupportedRelocMsg   db "halfexec: target uses relocation kinds outside the small supported set", 10
unsupportedRelocMsgLen = $ - unsupportedRelocMsg

stackStorageTooSmallMsg    db "halfexec: copied argv/env strings do not fit in the custom stack arena", 10
stackStorageTooSmallMsgLen = $ - stackStorageTooSmallMsg
openFailedMsg              db "halfexec: could not open the target ELF", 10
openFailedMsgLen           = $ - openFailedMsg
fstatFailedMsg             db "halfexec: could not stat the target ELF", 10
fstatFailedMsgLen          = $ - fstatFailedMsg
headerReadFailedMsg        db "halfexec: could not read the ELF header", 10
headerReadFailedMsgLen     = $ - headerReadFailedMsg
fileTooLargeMsg            db "halfexec: target is larger than the fixed staging buffer", 10
fileTooLargeMsgLen         = $ - fileTooLargeMsg
fileReadFailedMsg          db "halfexec: could not stage the target ELF into memory", 10
fileReadFailedMsgLen       = $ - fileReadFailedMsg
closeFailedMsg             db "halfexec: finished loading, but close() on the target file failed", 10
closeFailedMsgLen          = $ - closeFailedMsg
mmapFailedMsg              db "halfexec: mmap() failed while laying out the target image", 10
mmapFailedMsgLen           = $ - mmapFailedMsg
phdrReadFailedMsg          db "halfexec: could not read a PHDR from disk", 10
phdrReadFailedMsgLen       = $ - phdrReadFailedMsg
mprotectFailedMsg          db "halfexec: mprotect() rejected the final segment permissions", 10
mprotectFailedMsgLen       = $ - mprotectFailedMsg
archPrctlFailedMsg         db "halfexec: arch_prctl() failed while installing PT_TLS state", 10
archPrctlFailedMsgLen      = $ - archPrctlFailedMsg
forkFailedMsg              db "halfexec: fork() failed before the ET_EXEC trampoline path", 10
forkFailedMsgLen           = $ - forkFailedMsg
waitFailedMsg              db "halfexec: wait4() failed while supervising the ET_EXEC child", 10
waitFailedMsgLen           = $ - waitFailedMsg
