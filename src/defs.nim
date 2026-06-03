# defs.nim — NT type definitions
# Translated from defs.rs

type
  HANDLE*      = pointer
  PVOID*       = pointer
  SIZE_T*      = uint
  ULONG*       = uint32
  NTSTATUS*    = int32
  LARGE_INTEGER* = int64

const
  PAGE_READONLY*:        uint32 = 0x02
  PAGE_READWRITE*:       uint32 = 0x04
  PAGE_EXECUTE_READ*:    uint32 = 0x20
  PAGE_EXECUTE_READWRITE*: uint32 = 0x40
  IMAGE_DOS_SIGNATURE*:  uint16 = 0x5A4D
  WT_EXECUTEINTIMERTHREAD*: uint32 = 0x00000020

template NT_SUCCESS*(s: NTSTATUS): bool = s >= 0

type
  UNICODE_STRING* {.pure.} = object
    Length*:        uint16
    MaximumLength*: uint16
    Buffer*:        ptr uint16

  OBJECT_ATTRIBUTES* {.pure.} = object
    Length*:                   uint32
    RootDirectory*:            HANDLE
    ObjectName*:               ptr UNICODE_STRING
    Attributes*:               uint32
    SecurityDescriptor*:       pointer
    SecurityQualityOfService*: pointer

  IO_STATUS_BLOCK* {.pure.} = object
    Status*:      int32
    Information*: uint

  IMAGE_FILE_HEADER* {.pure.} = object
    Machine*:              uint16
    NumberOfSections*:     uint16
    TimeDateStamp*:        uint32
    PointerToSymbolTable*: uint32
    NumberOfSymbols*:      uint32
    SizeOfOptionalHeader*: uint16
    Characteristics*:      uint16

  IMAGE_SECTION_HEADER* {.pure.} = object
    Name*:                 array[8, uint8]
    VirtualSize*:          uint32
    VirtualAddress*:       uint32
    SizeOfRawData*:        uint32
    PointerToRawData*:     uint32
    PointerToRelocations*: uint32
    PointerToLinenumbers*: uint32
    NumberOfRelocations*:  uint16
    NumberOfLinenumbers*:  uint16
    Characteristics*:      uint32

  # 16-byte aligned buffer for CONTEXT (alignment enforced at call site)
  CONTEXT_BUF* = object
    data*: array[1232, uint8]

  USTRING* {.pure.} = object
    Length*:        uint32
    MaximumLength*: uint32
    Buffer*:        pointer
