# Prepares a symbols file for splat
#@author LemonHaze420
#@category splat
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.listing import CodeUnit
from java.io import FileWriter, BufferedWriter
from ghidra.util import Msg

listing = currentProgram.getListing()
function_manager = currentProgram.getFunctionManager()
functions = function_manager.getFunctions(True)

output_file = askFile("Choose output file", "Save")

writer = BufferedWriter(FileWriter(output_file))
seen_paths = set()

for function in functions:
    entry = function.getEntryPoint()
    code_unit = listing.getCodeUnitAt(entry)
    if code_unit is None:
        continue

    line = "{} \t\t\t\t= 0x{:08X}; // type:func\n".format(function.getName(), entry.getOffset())
    writer.write(line)

writer.close()
Msg.showInfo(None, None, "Export Complete", "Symbols list written to:\n{}".format(output_file.getAbsolutePath()))
