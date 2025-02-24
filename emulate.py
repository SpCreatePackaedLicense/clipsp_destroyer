from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.const import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *
from qiling.os.windows.api import *
from qiling.os.windows.structs import *
from qiling import *
from qiling.const import *

#
PAGE_MAP = {'0x1c00e6000': 'PAGEwx1', '0x1c00e7000': 'PAGEwx2', '0x1c00e8000': 'PAGEwx3', '0x1c00ec000': 'PAGEwx4', '0x1c00f2000': 'PAGEwx5', '0x1c00f6000': 'PAGEwx6'}
EMU_RANGES = [(7516404815, 7516404845), (7516913448, 7516913467), (7516932684, 7516932703), (7516955381, 7516955400), (7516957292, 7516957316)]
OLD_EMU_RANGES = []
#

EMU_RANGES = list(set(EMU_RANGES) - set(OLD_EMU_RANGES))

@winsdkapi(cc=STDCALL, params={"FastMutex": POINTER})
def hook_ExAcquireFastMutex(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, params={"FastMutex": POINTER})
def hook_ExReleaseFastMutex(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, params={"FastMutex": POINTER})
def hook_KeReleaseGuardedMutex(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, params={
        "VirtualAddress": POINTER,
        "Length": ULONG,
        "SecondaryBuffer": BOOLEAN,
        "ChargeQuota": BOOLEAN,
        "Irp": POINTER,
    })
def hook_IoAllocateMdl(ql, address, params):
    objcls = {
        QL_ARCH.X86   : make_mdl(32),
        QL_ARCH.X8664 : make_mdl(64)
    }[ql.arch.type]

    mdl = objcls()
    addr = ql.os.heap.alloc(ctypes.sizeof(objcls))  

    mdl.Next = 0
    mdl.Size = params['Length']
    mdl.MdlFlags = 1 # locked
    mdl.Process = 0
    mdl.MappedSystemVa = params['VirtualAddress']
    mdl.StartVa = params['VirtualAddress']
    mdl.ByteCount = params['Length']
    mdl.ByteOffset = 0

    ql.mem.write(addr, bytes(mdl)[:])
    
    return addr


@winsdkapi(cc=STDCALL, params={"MemoryDescriptorList": POINTER,"AccessMode": ULONG,"Operation": ULONG})
def hook_MmProbeAndLockPages(ql, addr, params):
    return None


# might need to update MDL VA member
@winsdkapi(cc=STDCALL, params={
        "MemoryDescriptorList": POINTER,
        "VirtualAddress": POINTER,
        "Size": ULONG,
        "Flags": ULONG,
    })
def hook_MmChangeImageProtection(ql, addr, params):
    return True


@winsdkapi(cc=STDCALL, params={"AddressWithinSection": POINTER})
def hook_MmLockPagableImageSection(ql, addr, params):
    return params["AddressWithinSection"]


@winsdkapi(cc=STDCALL, params={"ImageSectionHandle": POINTER})
def hook_MmUnlockPagableImageSection(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, params={"MemoryDescriptorList": POINTER})
def hook_MmUnlockPages(ql, addr, params):
    MemoryDescriptorList = params['MemoryDescriptorList']
    
    if ql.arch.type == QL_ARCH.X8664:
        mdl_buffer = ql.mem.read(MemoryDescriptorList, ctypes.sizeof(make_mdl(64)))
        mdl = make_mdl(64).from_buffer(mdl_buffer)
        mdl.Flags = 0 
    else:
        mdl_buffer = ql.mem.read(MemoryDescriptorList, ctypes.sizeof(make_mdl(32)))
        mdl = make_mdl(32).from_buffer(mdl_buffer)
        mdl.Flags = 0

    ql.mem.write(addr, bytes(mdl)[:])


@winsdkapi(cc=STDCALL, params={"Mdl": POINTER})
def hook_IoFreeMdl(ql, address, params):
    addr = params['Mdl']
    
    if ql.arch.type == QL_ARCH.X8664:
        mdl_buffer = ql.mem.read(addr, ctypes.sizeof(make_mdl(64)))
        mdl = make_mdl(64).from_buffer(mdl_buffer)
    else:
        mdl_buffer = ql.mem.read(addr, ctypes.sizeof(make_mdl(32)))
        mdl = make_mdl(32).from_buffer(mdl_buffer)

    size = mdl.Size
    va = mdl.StartVa

    print(hex(va))

    if name := PAGE_MAP.get(hex(va)):
        print(f"Dumping {hex(size)} bytes to section_{name}")
        mem = ql.mem.read(va, size)
        with open("patch.py", "a+") as f:
            f.write(f"""ida_bytes.patch_bytes({va}, bytes.fromhex("{bytes(mem).hex()}"))\n""")
        # ida_bytes.patch_bytes(va, bytes(mem))
        # with open(f"section_{name}", "wb") as f:
        #     f.write(mem)
    
    ql.os.heap.free(addr)
    
    return None


@winsdkapi(cc=STDCALL, params={"BaseAddress": POINTER, "MemoryDescriptorList": POINTER})
def hook_MmUnmapLockedPages(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, params={"PushLock": POINTER, "Flags": ULONG})
def hook_FltAcquirePushLockSharedEx(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, params={"PushLock": POINTER, "Flags": ULONG})
def hook_FltAcquirePushLockExclusiveEx(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, params={"PushLock": POINTER, "Flags": ULONG})
def hook_FltReleasePushLockEx(ql, addr, params):
    return None


@winsdkapi(cc=STDCALL, params={"PushLock": POINTER})
def hook_FltInitializePushLock(ql, addr, params):
    return None


# read string from memory address
def readstr_wide(ql, addr):
    res = ""
    while True:
        # read one byte at a time
        c = ql.mem.read(addr, 2).decode()
        if c == '\x00\x00':
            break
        res += c
        addr += 2
    return res


@winsdkapi(cc=STDCALL, params={
        "SourceID": POINTER,
        "CustomValue": POINTER,
        "DefaultPath": POINTER,
        "StateLocationType": ULONG,
        "TargetPath": POINTER,
        "BufferLengthIn": ULONG,
        "BufferLengthOut": POINTER,
    })
def hook_RtlGetPersistedStateLocation(ql, address, params):
    srcid = params["SourceID"]
    custom = params["CustomValue"]
    state_type = params["StateLocationType"]
    target = params["TargetPath"]

    keys = ["\Registry\Machine\System\CurrentControlSet\Control\StateSeparation\RedirectionMap\Keys",
            "\Registry\Machine\System\CurrentControlSet\Control\StateSeparation\RedirectionMap\Files"]

    key = keys[state_type]
    print(f"key: {key}")
    print(f"srcid: {readstr_wide(ql, srcid)} {readstr_wide(ql, custom)}")
    
    ql.os.registry_manager.access(key)
    
    return 0


def emulate(start, end):
    ql = Qiling(["ClipSp.sys"], "./x8664_windows", verbose=QL_VERBOSE.OFF)

    md = ql.arch.disassembler
    md.detail = True

    ql.os.set_api("ExAcquireFastMutex", hook_ExAcquireFastMutex)
    ql.os.set_api("ExReleaseFastMutex", hook_ExReleaseFastMutex)
    ql.os.set_api("IoAllocateMdl", hook_IoAllocateMdl)
    ql.os.set_api("MmProbeAndLockPages", hook_MmProbeAndLockPages)
    ql.os.set_api("MmChangeImageProtection", hook_MmChangeImageProtection)
    ql.os.set_api("MmLockPagableImageSection", hook_MmLockPagableImageSection)
    ql.os.set_api("MmUnlockPages", hook_MmUnlockPages)
    ql.os.set_api("IoFreeMdl", hook_IoFreeMdl)
    ql.os.set_api("MmUnmapLockedPages", hook_MmUnmapLockedPages)
    ql.os.set_api("KeReleaseGuardedMutex", hook_KeReleaseGuardedMutex)
    ql.os.set_api("FltAcquirePushLockSharedEx", hook_FltAcquirePushLockSharedEx)
    ql.os.set_api("FltReleasePushLockEx", hook_FltReleasePushLockEx)
    ql.os.set_api("MmUnlockPagableImageSection", hook_MmUnlockPagableImageSection)
    ql.os.set_api("FltAcquirePushLockExclusiveEx", hook_FltAcquirePushLockExclusiveEx)
    ql.os.set_api("RtlGetPersistedStateLocation", hook_RtlGetPersistedStateLocation)
    ql.os.set_api("FltInitializePushLock", hook_FltInitializePushLock)

    ql.arch.regs.rcx = 0
    ql.arch.regs.rdx = ql.os.heap.alloc(0x30)

    ql.run(begin=start, end=end)

for (start, end) in EMU_RANGES:
    emulate(start, end)