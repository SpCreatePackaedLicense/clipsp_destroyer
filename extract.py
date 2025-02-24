import bisect, idaapi, ida_allins, idautils, ida_ua, ida_funcs, idc

# what could possibly go wrong
CRYPT_MUTEX = 0x00000001C00A1ED8

crypt_calls = {}
for crypt_handler in map(lambda x: ida_funcs.get_func(x.frm).start_ea, idautils.XrefsTo(CRYPT_MUTEX)):
    for crypt_call in map(lambda x: x.frm, idautils.XrefsTo(crypt_handler)):
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, crypt_call)
        if insn.itype != ida_allins.NN_call or not ida_funcs.get_func(crypt_call): continue
        
        func = ida_funcs.get_func(crypt_call)
        key = (func.start_ea, func.end_ea)
        if key not in crypt_calls: crypt_calls[key] = []
        bisect.insort(crypt_calls[key], crypt_call)

chosen_decryptors = {}
for (func_start, func_end), crypt_calls in crypt_calls.items():
    crypt_status = {}
    for crypt_call in crypt_calls:
        ea = crypt_call
        while ea != func_start and ea != idaapi.BADADDR:
            insn = idaapi.insn_t()
            length = idaapi.decode_insn(insn, ea)
            if insn.itype == ida_allins.NN_lea and insn.ops[0].type == ida_ua.o_reg and insn.ops[1].type == ida_ua.o_mem:
                if insn.ops[0].reg == idautils.procregs.rcx.reg:
                    data = insn.ops[1].addr
                    encrypted = crypt_status.get(data, False)
                    if not encrypted and not data in chosen_decryptors: chosen_decryptors[data] = (func_start, func_end, crypt_call)
                    crypt_status[data] = not encrypted
                    break
            ea = idaapi.prev_head(ea, func_start)

emu_ranges = []
for (func_start, func_end, chosen_decryptor) in chosen_decryptors.values():
    ea = chosen_decryptor
    hit = { idautils.procregs.rcx.reg: False, idautils.procregs.rdx.reg: False }
    while ea != func_start and ea != idaapi.BADADDR:
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, ea)
        if insn.itype == ida_allins.NN_lea and insn.ops[0].type == ida_ua.o_reg and insn.ops[1].type == ida_ua.o_mem:
            reg = insn.ops[0].reg
            if reg in hit: hit[reg] = True
            if all(hit.values()):
                emu_ranges.append((ea, idaapi.next_head(chosen_decryptor, func_end)))
                break
        ea = idaapi.prev_head(ea, func_start)

page_map = { hex(addr): idc.get_segm_name(int(addr)) for addr in idautils.Segments() if "PAGEwx" in idc.get_segm_name(int(addr)) }

print(f"""PAGE_MAP = {page_map}""")
print(f"""EMU_RANGES = {emu_ranges}""")