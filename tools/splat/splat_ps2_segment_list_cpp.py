# Prepares a segment list based on populated plate comments 
#@author LemonHaze420
#@category splat
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.listing import CodeUnit

def va_to_file_offset(va, base_va=0x00100000, base_file_offset=0x1000):
    return va - base_va + base_file_offset

listing = currentProgram.getListing()
function_manager = currentProgram.getFunctionManager()
functions = function_manager.getFunctions(True)

seen_paths = set()

for function in functions:
    entry = function.getEntryPoint()
    code_unit = listing.getCodeUnitAt(entry)
    if code_unit is None:
        continue

    comment = code_unit.getComment(CodeUnit.PLATE_COMMENT)
    if not comment:
        continue
    first_line = comment.strip().splitlines()[0].strip()
    if not first_line:
        continue

    path = first_line.split()[0].strip()

    if path in seen_paths:
        continue
    seen_paths.add(path)

    va = entry.getOffset()
    file_offset = va_to_file_offset(va)

    print("  - [0x{:X}, asm, {}]".format(file_offset, path))
