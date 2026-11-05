// Print a bounded instruction slice by address from a named function, crossing basic blocks.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import java.util.ArrayList;
import java.util.List;

public class GhidraPrintFunctionSlice extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            println("usage: <function-name> <center-address> <radius-in-instructions>");
            return;
        }
        Function target = findFunction(args[0]);
        if (target == null) throw new IllegalArgumentException("function not found: " + args[0]);
        int radius = Integer.parseInt(args[2]);
        if (radius < 0 || radius > 256) throw new IllegalArgumentException("radius out of range");
        var center = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(args[1]);
        Listing listing = currentProgram.getListing();
        List<Instruction> instructions = new ArrayList<Instruction>();
        int centerIndex = -1;
        for (Instruction instruction : listing.getInstructions(target.getBody(), true)) {
            if (instruction.getAddress().equals(center)) centerIndex = instructions.size();
            instructions.add(instruction);
        }
        if (centerIndex < 0) {
            println("function_slice function=" + target.getName() + " center=" + center
                + " status=not_in_function");
            return;
        }
        int first = Math.max(0, centerIndex - radius);
        int last = Math.min(instructions.size() - 1, centerIndex + radius);
        println("function_slice_begin function=" + target.getName() + " center=" + center
            + " instruction_count=" + instructions.size());
        for (int i = first; i <= last; i++) {
            Instruction instruction = instructions.get(i);
            println("  " + instruction.getAddress() + "  " + instruction
                + (i == centerIndex ? "  --- center ---" : ""));
        }
        println("function_slice_end function=" + target.getName() + " center=" + center);
    }

    private Function findFunction(String name) {
        Function found = null;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function candidate = functions.next();
            if (candidate.getName().equals(name)) {
                if (found != null) throw new IllegalStateException("ambiguous function: " + name);
                found = candidate;
            }
        }
        return found;
    }
}
