// Find every instruction in one named function that references one stack slot.
// Read-only helper for tracing a local pointer across setup and callback paths.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.address.AddressSetView;

public class GhidraFindStackSlot extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            println("usage: <function-name> <operand-text>");
            return;
        }
        Function target = null;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function candidate = functions.next();
            if (candidate.getName().equals(args[0])) {
                if (target != null) {
                    throw new IllegalStateException("function name is ambiguous: " + args[0]);
                }
                target = candidate;
            }
        }
        if (target == null) {
            throw new IllegalArgumentException("function not found: " + args[0]);
        }

        AddressSetView body = target.getBody();
        Listing listing = currentProgram.getListing();
        int matches = 0;
        for (Instruction instruction : listing.getInstructions(body, true)) {
            if (instruction.toString().contains(args[1])) {
                println("stack_slot_ref function=" + target.getName()
                    + " address=" + instruction.getAddress()
                    + " instruction=" + instruction);
                matches++;
            }
        }
        println("stack_slot_summary function=" + target.getName()
            + " operand=" + args[1] + " matches=" + matches);
    }
}
