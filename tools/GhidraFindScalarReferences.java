// Read-only scan for instructions that encode a selected scalar/displacement.
// Use this to locate candidate initializers or users of a structure field when
// Ghidra pseudocode expresses it as `base + DAT_<offset>`. Results are only
// candidate references; inspect each instruction and its containing function.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;

public class GhidraFindScalarReferences extends GhidraScript {
    @Override
    public void run() throws Exception {
        long wanted = getScriptArgs().length == 0
            ? 0x2110L
            : Long.decode(getScriptArgs()[0]);
        int matches = 0;
        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            boolean found = false;
            for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                for (Object object : instruction.getOpObjects(operand)) {
                    if (object instanceof Scalar
                            && ((Scalar) object).getUnsignedValue() == wanted) {
                        found = true;
                        break;
                    }
                }
                if (found) break;
            }
            if (!found) continue;
            Function function = currentProgram.getFunctionManager()
                .getFunctionContaining(instruction.getAddress());
            println("scalar_reference=0x" + Long.toHexString(wanted)
                + " address=" + instruction.getAddress()
                + " function=" + (function == null ? "unknown" : function.getName())
                + " instruction=" + instruction);
            matches++;
        }
        println("scalar_reference_summary=0x" + Long.toHexString(wanted)
            + " count=" + matches);
    }
}
