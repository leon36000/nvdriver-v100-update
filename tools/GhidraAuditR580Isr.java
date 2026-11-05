// Bounded, read-only Ghidra decompilation of proprietary R580 interrupt entry points.
// Run with analyzeHeadless -import <nv-kernel.o_binary> -postScript GhidraAuditR580Isr.java.
// Output is analysis evidence, not NVIDIA source or proof of runtime lock behavior.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.util.Set;
import java.util.TreeSet;

public class GhidraAuditR580Isr extends GhidraScript {
    private static final String[] DEFAULT_FUNCTIONS = {
        "rm_isr", "rm_isr_bh", "rm_gpu_handle_mmu_faults"
    };

    @Override
    public void run() throws Exception {
        println("program=" + currentProgram.getName());
        println("language=" + currentProgram.getLanguageID());
        println("imageBase=" + currentProgram.getImageBase());
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            String[] targets = getScriptArgs().length == 0 ? DEFAULT_FUNCTIONS : getScriptArgs();
            for (String name : targets) {
                Function function = findFunction(name);
                if (function == null) {
                    println("function=" + name + " status=missing");
                    continue;
                }
                printFunction(decompiler, function);
            }
        } finally {
            decompiler.dispose();
        }
    }

    private Function findFunction(String name) {
        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(name);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getName().equals(name)) {
                Function function = currentProgram.getFunctionManager()
                    .getFunctionAt(symbol.getAddress());
                if (function != null) return function;
            }
        }
        return null;
    }

    private void printFunction(DecompInterface decompiler, Function function) throws Exception {
        Address entry = function.getEntryPoint();
        println("function=" + function.getName()
            + " entry=" + entry
            + " body=" + function.getBody()
            + " thunk=" + function.isThunk()
            + " external=" + function.isExternal());

        Set<String> callTargets = new TreeSet<String>();
        for (Address address : function.getBody().getAddresses(true)) {
            for (Reference reference : currentProgram.getReferenceManager()
                    .getReferencesFrom(address)) {
                if (reference.getReferenceType().isCall()) {
                    Address target = reference.getToAddress();
                    Function callee = currentProgram.getFunctionManager()
                        .getFunctionAt(target);
                    String label = callee == null ? "unresolved" : callee.getName();
                    callTargets.add(reference.getReferenceType() + " " + target + " " + label);
                }
            }
        }
        for (String target : callTargets) println("  call=" + target);

        ReferenceIterator callers = currentProgram.getReferenceManager().getReferencesTo(entry);
        while (callers.hasNext()) {
            Reference reference = callers.next();
            Function caller = currentProgram.getFunctionManager()
                .getFunctionContaining(reference.getFromAddress());
            println("  incoming type=" + reference.getReferenceType()
                + " from=" + reference.getFromAddress()
                + " caller=" + (caller == null ? "unknown" : caller.getName()));
        }

        DecompileResults result = decompiler.decompileFunction(function, 90, monitor);
        if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
            println("decompile status=failed error=" + result.getErrorMessage());
            return;
        }
        println("decompile status=complete");
        println("decompiled_c_begin " + function.getName());
        println(result.getDecompiledFunction().getC());
        println("decompiled_c_end " + function.getName());
    }
}
