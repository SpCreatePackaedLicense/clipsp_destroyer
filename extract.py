from functools import reduce
import bisect, idaapi, ida_allins, idautils, ida_ua, ida_funcs, idc

def get_reg_assign(start_ea, end_ea, reg, filter = lambda i: True):
    ea = end_ea
    while ea != start_ea and ea != idaapi.BADADDR:
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, ea)
        if (
            insn.ops[0].type == ida_ua.o_reg
            and insn.ops[0].reg == getattr(idautils.procregs, reg).reg
            and filter(insn)
        ):
            return ea
        ea = idaapi.prev_head(ea, start_ea)
    return idaapi.BADADDR

def h_find_mutex():
    initialize_evt = idc.get_name_ea(0, "KeInitializeEvent")

    for call in idautils.XrefsTo(initialize_evt):
        calling_func = ida_funcs.get_func(call.frm)

        # Called once by driver entry
        candidates = filter(
            lambda ref: getattr(ida_funcs.get_func(ref.frm), "name", "") == "DriverEntry",
            idautils.XrefsTo(calling_func.start_ea)
        )

        if next(candidates, None):
            insn = idaapi.insn_t()
            idaapi.decode_insn(insn, get_reg_assign(calling_func.start_ea, call.frm, "rcx"))
            # rcx is FastMutex.Event (offset 0x18)
            mutex = insn.ops[1].addr - 0x18
            return mutex
    return None

fallback_mutex = None
mutex = h_find_mutex() or fallback_mutex
if not mutex: raise Exception("couldn't find mutex")

"""
Find all references to the CRYPT_MUTEX, these are the (en/de)cryption handlers
Find all references to these handlers which are CALLs (PAGEwx6 stores their addresses somewhere for some fucking reason)
Store all the addresses of call instructions and organise by function 
"""
def get_crypt_calls(mutex):
    # Two refs per handler - [AcquireFastMutex, ReleaseFastMutex]
    crypt_calls = {}
    for crypt_handler in set(
            map(lambda mutex_ref: ida_funcs.get_func(mutex_ref.frm).start_ea, idautils.XrefsTo(mutex))
        ):
        for crypt_call in map(lambda handler_ref: handler_ref.frm, idautils.XrefsTo(crypt_handler)):
            insn = idaapi.insn_t()
            length = idaapi.decode_insn(insn, crypt_call)
            if insn.itype != ida_allins.NN_call or not ida_funcs.get_func(crypt_call): continue
            
            func = ida_funcs.get_func(crypt_call)
            key = (func.start_ea, func.end_ea)
            if key not in crypt_calls: crypt_calls[key] = []
            bisect.insort(crypt_calls[key], crypt_call)

    return crypt_calls

"""
Deduce which are encryptors, which are decryptors
"""
def choose_decryptors(crypt_calls):
    chosen_decryptors = {}
    for (func_start, func_end), crypt_calls in crypt_calls.items():
        crypt_status = {}
        for crypt_call in crypt_calls:
            ea = get_reg_assign(func_start, crypt_call, "rcx", lambda i: i.itype == ida_allins.NN_lea and i.ops[1].type == ida_ua.o_mem)
            if ea == idaapi.BADADDR: continue

            insn = idaapi.insn_t()
            length = idaapi.decode_insn(insn, ea)

            data = insn.ops[1].addr
            encrypted = crypt_status.get(data, True)
            if encrypted:
                print(f"discovered {ea:08X} {crypt_call:08X} processing blob {data:08X} (decryptor)")
                if data not in chosen_decryptors:
                    chosen_decryptors[data] = (func_start, func_end, crypt_call)
                crypt_status[data] = False
                continue
            else:
                print(f"discovered {ea:08X} {crypt_call:08X} processing blob {data:08X} (encryptor)")
                crypt_status[data] = True
    return chosen_decryptors

def get_emu_ranges(chosen_decryptors):
    emu_ranges = []
    for (func_start, func_end, chosen_decryptor) in chosen_decryptors.values():
        chosen_decryptor
        pred = lambda i: i.itype == ida_allins.NN_lea and i.ops[1].type == ida_ua.o_mem
        emu_start = min(
            get_reg_assign(func_start, chosen_decryptor, "rcx", pred),
            get_reg_assign(func_start, chosen_decryptor, "rdx", pred)
        )
        emu_end = idaapi.next_head(chosen_decryptor, func_end)
        emu_ranges.append((emu_start, emu_end))
    return emu_ranges

steps = [h_find_mutex, get_crypt_calls, choose_decryptors, get_emu_ranges]

emu_ranges = reduce(lambda acc, f: f(acc), steps[1:], steps[0]())

page_map = { hex(addr): idc.get_segm_name(int(addr)) for addr in idautils.Segments() if "PAGEwx" in idc.get_segm_name(int(addr)) }

print(f"""PAGE_MAP = {page_map}""")
print(f"""EMU_RANGES = {emu_ranges}""")
