# dpapi.nim — Credential blob encryption/decryption via CryptProtectData / CryptUnprotectData

import winim

proc dpapiEncrypt*(plaintext: seq[byte]): seq[byte] =
  # unsafe
  var inBlob = DATA_BLOB(
    cbData: DWORD(plaintext.len),
    pbData: if plaintext.len > 0: cast[PBYTE](unsafeAddr plaintext[0]) else: nil)
  var outBlob = DATA_BLOB(cbData: 0, pbData: nil)

  if CryptProtectData(
    addr inBlob, nil, nil, nil, nil,
    CRYPTPROTECT_LOCAL_MACHINE,
    addr outBlob) == 0:
    return @[]

  var data = newSeq[byte](int(outBlob.cbData))
  copyMem(addr data[0], outBlob.pbData, int(outBlob.cbData))
  discard LocalFree(cast[HLOCAL](outBlob.pbData))
  result = data

proc dpapiDecrypt*(ciphertext: seq[byte]): seq[byte] =
  # unsafe
  var inBlob = DATA_BLOB(
    cbData: DWORD(ciphertext.len),
    pbData: if ciphertext.len > 0: cast[PBYTE](unsafeAddr ciphertext[0]) else: nil)
  var outBlob = DATA_BLOB(cbData: 0, pbData: nil)

  if CryptUnprotectData(
    addr inBlob, nil, nil, nil, nil,
    0,
    addr outBlob) == 0:
    return @[]

  var data = newSeq[byte](int(outBlob.cbData))
  copyMem(addr data[0], outBlob.pbData, int(outBlob.cbData))
  discard LocalFree(cast[HLOCAL](outBlob.pbData))
  result = data
