// Read-only scan for pointer-identity clues: memory stores with no explicit displacement.
// This does not infer object identity; it only narrows stores for manual def-use review.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import java.util.regex.Pattern;

public class GhidraFindZeroOffsetStores extends GhidraScript {
    private static final Pattern ZERO_DISPLACEMENT =
        Pattern.compile(".*\\[(?:R[A-Z0-9]+|E[A-Z0-9]+)\\].*");

    @Override
    public void run() throws Exception {
        String[] names = getScriptArgs();
        if (names.length == 0) {
            println("usage: <function-name> [function-name ...]");
            return;
        }
        Listing listing = currentProgram.getListing();
        for (String name : names) {
            Function target = findFunction(name);
            if (target == null) {
                println("zero_offset_store_function=" + name + " status=missing");
                continue;
            }
            int matches = 0;
            for (Instruction instruction : listing.getInstructions(target.getBody(), true)) {
                if (!ZERO_DISPLACEMENT.matcher(instruction.toString()).matches()) continue;
                boolean isStore = false;
                for (PcodeOp op : instruction.getPcode()) {
                    if (op.getOpcode() == PcodeOp.STORE) {
                        isStore = true;
                        break;
                    }
                }
                if (isStore) {
                    println("zero_offset_store function=" + target.getName()
                        + " address=" + instruction.getAddress()
                        + " instruction=" + instruction);
                    matches++;
                }
            }
            println("zero_offset_store_summary function=" + target.getName()
                + " matches=" + matches);
        }
    }

    private Function findFunction(String name) {
        Function found = null;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function candidate = functions.next();
            if (candidate.getName().equals(name)) {
                if (found != null) {
                    throw new IllegalStateException("function name is ambiguous: " + name);
                }
                found = candidate;
            }
        }
        return found;
    }
}
