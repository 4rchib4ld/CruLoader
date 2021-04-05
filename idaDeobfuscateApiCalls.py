import pefile, os, re, binascii

dlls_list = ["kernel32.dll", "ntdll.dll", "wininet.dll"]

#Get the list of all functions inside the dll
def get_functions(dll_path):
	pe = pefile.PE(dll_path)
	if ((not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT')) or (pe.DIRECTORY_ENTRY_EXPORT is None)):
		print(f"[*] No exports for {dll_path}")
		return []
	else:
		expname = []
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			if exp.name:
				expname.append(exp.name)
		return expname

# Hash the function name
def calc_crc32(string): 
	return int(binascii.crc32(string) & 0xFFFFFFFF)

# Generate CRC32 lookup table
win_path = os.environ['WINDIR']
system32_path = os.path.join(win_path, "system32")
data = {}
for dll in dlls_list:
	dll_path = os.path.join(system32_path, dll)
	dll_name = dll.split(".")[0].lower()
	if os.path.isfile(dll_path):
		for f in get_functions(dll_path):
			f_name = re.sub(r'\W+', '_', f.decode('utf-8'))
			name = "func_"+dll_name + "_" + f_name.lower()
			data[calc_crc32(f)] = name
		print(f"[+] Generated functions for {dll_path}")
	else:
		print(f"[*] File not found: {dll_path}")

# List all Xref to the function, retrieve the content of edx (where the crc32 hash is) and compare it to our crc32 lookup table. A comment is set if there is a hit
for xref in XrefsTo(get_name_ea_simple("f_getProcAddr")):
	currentAddress = 0
	ea = xref.frm
	for i in range(0,20):
		mnem = print_insn_mnem(prev_head(ea-i))
		if mnem == "mov":
			if print_operand(prev_head(ea-i), 0) == "edx":
				crc32_value = print_operand(prev_head(ea-i), 1)
				crc32_value = int(crc32_value[:-1], 16)
				for k, v in data.items():
					if k == crc32_value:
						set_cmt(xref.frm, v, 0)
				break
