// Print a small read-only disassembly window around one or more addresses.
// The addresses must use the current Ghidra program address space.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;

public class GhidraPrintInstructionWindow extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("usage: <radius> <address> [address ...]");
            return;
        }
        int radius = Integer.parseInt(args[0]);
        if (radius < 0 || radius > 64) {
            throw new IllegalArgumentException("radius must be in [0,64]");
        }
        Program program = currentProgram;
        Listing listing = program.getListing();
        for (int index = 1; index < args.length; index++) {
            Address centerAddress = program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(args[index]);
            Instruction center = listing.getInstructionContaining(centerAddress);
            if (center == null) {
                println("window address=" + centerAddress + " status=no_instruction");
                continue;
            }
            Function function = program.getFunctionManager()
                .getFunctionContaining(center.getAddress());
            println("window_begin address=" + centerAddress
                + " function=" + (function == null ? "unknown" : function.getName()));
            Instruction first = center;
            for (int n = 0; n < radius; n++) {
                Instruction previous = listing.getInstructionBefore(first.getAddress());
                if (previous == null) break;
                first = previous;
            }
            Instruction current = first;
            int limit = radius * 2 + 1;
            for (int n = 0; current != null && n < limit; n++) {
                println("  " + current.getAddress() + "  " + current);
                if (current.getAddress().equals(center.getAddress())) println("  --- center ---");
                current = listing.getInstructionAfter(current.getAddress());
            }
            println("window_end address=" + centerAddress);
        }
    }
}
