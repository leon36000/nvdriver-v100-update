// Inspect selected pointer-sized slots relative to global pointer values in a
// read-only Ghidra program. This does not infer the slot's type or relocation
// semantics. Arguments: <slot-offset> [...] -- <global-pointer> [...].
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;

public class GhidraResolvePointerSlots extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        int separator = -1;
        for (int index = 0; index < args.length; index++) {
            if (args[index].equals("--")) {
                separator = index;
                break;
            }
        }
        if (separator < 1 || separator == args.length - 1) {
            println("usage: <slot-offset> [...] -- <global-pointer-address> [...]");
            return;
        }
        AddressSpace defaultSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
        for (int globalIndex = separator + 1; globalIndex < args.length; globalIndex++) {
            String globalText = args[globalIndex];
            Address globalAddress = defaultSpace.getAddress(globalText);
            long tableValue = currentProgram.getMemory().getLong(globalAddress);
            Address tableAddress = defaultSpace.getAddress(Long.toHexString(tableValue));
            Symbol globalSymbol = currentProgram.getSymbolTable().getPrimarySymbol(globalAddress);
            println("pointer_global=" + globalAddress
                + " symbol=" + (globalSymbol == null ? "unknown" : globalSymbol.getName())
                + " table=" + (tableValue == 0 ? "null" : tableAddress));
            if (tableValue == 0) continue;
            for (int index = 0; index < separator; index++) {
                long offset = Long.decode(args[index]);
                Address slot = tableAddress.add(offset);
                long targetValue = currentProgram.getMemory().getLong(slot);
                Address target = defaultSpace.getAddress(Long.toHexString(targetValue));
                Function function = currentProgram.getFunctionManager().getFunctionAt(target);
                Symbol targetSymbol = currentProgram.getSymbolTable().getPrimarySymbol(target);
                println("  slot=+0x" + Long.toHexString(offset)
                    + " address=" + slot
                    + " target=" + target
                    + " function=" + (function == null ? "unknown" : function.getName())
                    + " symbol=" + (targetSymbol == null ? "unknown" : targetSymbol.getName()));
            }
        }
    }
}
