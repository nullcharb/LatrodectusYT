# Reference Code Used: https://github.com/leandrofroes/malware-research/blob/main/Latrodectus/binja_latrodectus_str_dec.py

import idaapi, idc, idautils

def find_fn_Xrefs(fn_addr):

    xref_list = []

    for ref in idautils.XrefsTo(fn_addr):
        xref = {}
        xref['normal'] = ref.frm
        xref['hex'] = hex(ref.frm)
        xref_list.append(xref)

    return xref_list


def get_bytes_from_address(addr, length):
    ea = addr
    ret_data = bytearray()
    for i in range(0,length):
        data = idc.get_bytes(ea+i, 1)
        ret_data.append(data[0])
        i += 1

    return ret_data


def get_fastcall_args_number(fn_addr, arg_number):
    args = []
    arg_count = 0
    ptr_addr = fn_addr
    while True:
        ptr_addr = idc.prev_head(ptr_addr)
        # print(idc.print_insn_mnem(ptr_addr))
        if idc.print_insn_mnem(ptr_addr) == 'mov' or idc.print_insn_mnem(ptr_addr) == 'lea':
            arg_count += 1
            if arg_count == arg_number:
                if idc.get_operand_type(ptr_addr, 1) == idc.o_mem:
                    args.append(idc.get_operand_value(ptr_addr, 1))
                elif idc.get_operand_type(ptr_addr, 1) == idc.o_imm:
                    args.append(idc.get_operand_value(ptr_addr, 1))
                elif idc.get_operand_type(ptr_addr, 1) == idc.o_reg:
                    reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 1), 4)
                    reg_value = get_reg_value(ptr_addr, reg_name)
                    args.append(reg_value)
                else:
                    ## We can't handle pushing reg values so throw error
                    print("Exception in get_stack_args")
                    return
                return args
            else:
                continue
    return args


def decode_str(s) -> str:
	is_wide_str = len(s) > 1 and s[1] == 0

	result_str = ""

	if not is_wide_str:
		result_str = s.decode("utf8")
	else:
		result_str = s.decode("utf-16le")
		
	if result_str.isascii():
		return result_str
	
	return ""


def decrypt(a1):
    result = bytearray()
    key = a1[0]
    result_len = a1[4] ^ a1[0]
    v8 = 6  # Offset to the third element in a1 as bytes
    extracted_data = a1[6:6+result_len]

    for i in range(result_len):
        key = key + 1
        print(f"Debug: key: {hex(key)}, extracted_data[i] : {hex(extracted_data[i])}, result: {extracted_data[i] ^ key}")
        result.append(extracted_data[i] ^ key)
        
    print(f"Debug: {len(result)} | {result}")
    return decode_str(result)
    

def set_hexrays_comment(address,text):
    print("Setting hex rays comment")
    # breakpoint()
    cfunc = idaapi.decompile(address)
    tl = idaapi.treeloc_t()
    tl.ea = address
    tl.itp = idaapi.ITP_SEMI

    if cfunc:
      cfunc.set_user_cmt(tl, text)
      cfunc.save_user_cmts()
    else:
      print("Decompile failed: {:#x}".format(address)) 


def set_comment(address,text):
    idc.set_cmt(address,text,0)
    set_hexrays_comment(address,text)


decryption_fn_address = 0x000000018000ACC8
# get the xrefs to the function address
xref_list = find_fn_Xrefs(decryption_fn_address)
# for each ref in the array
for ref in xref_list:
    print("")
    print(f"Func Address : {ref['hex']}, {ref['normal']}")
    arg_address_hex = hex(get_fastcall_args_number(ref['normal'],1)[0]) 
    arg_address = get_fastcall_args_number(ref['normal'],1)[0]
    enc_value = get_bytes_from_address(arg_address, 8)
    # print(f"env value: {enc_value}")
    print(f"Debug: enc_value[0] : {hex(enc_value[0])}, enc_value[4]: {hex(enc_value[4])}")
    result_str_len = enc_value[0] ^ enc_value[4]
    print(f"result char count : {result_str_len}")
    enc_value = get_bytes_from_address(arg_address, 6 + result_str_len)
    if b'\xff\xff\xff\xff' not in enc_value:
        print(f"Debug: len : {len(enc_value)}, enc_value: {enc_value}")
        dec_string = decrypt(enc_value)
        print(f"Decrypted String: {dec_string}")
        set_comment(ref['normal'], dec_string)

