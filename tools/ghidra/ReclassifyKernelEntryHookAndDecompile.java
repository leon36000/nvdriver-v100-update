// Ghidra-only metadata adjustment for Linux kernel entry instrumentation.
// The imported ELF is never modified. Run as a postScript with three arguments:
// <target-function> <entry-hook-symbol> <new-output-file>.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class ReclassifyKernelEntryHookAndDecompile extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException(
                "expected: <target-function> <entry-hook-symbol> <new-output-file>");
        }

        String targetName = args[0];
        String hookName = args[1];
        Path outputPath = Paths.get(args[2]);
        if (Files.exists(outputPath)) {
            throw new IllegalStateException("refusing to overwrite output: " + outputPath);
        }

        Function target = null;
        Function entryHook = null;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (targetName.equals(function.getName())) {
                if (target != null) {
                    throw new IllegalStateException("multiple target functions found: " + targetName);
                }
                target = function;
            }
            if (hookName.equals(function.getName())) {
                if (entryHook != null) {
                    throw new IllegalStateException("multiple entry-hook functions found: " + hookName);
                }
                entryHook = function;
            }
        }

        if (target == null) {
            throw new IllegalStateException("target function not found: " + targetName);
        }
        if (entryHook == null) {
            throw new IllegalStateException("entry-hook function not found: " + hookName);
        }
        if (!entryHook.isThunk() || entryHook.isExternal()) {
            throw new IllegalStateException(
                "entry-hook is not the expected internal thunk: " + hookName);
        }

        int transaction = currentProgram.startTransaction(
            "Correct entry-hook flow metadata for targeted decompilation");
        boolean commit = false;
        try {
            println("entry hook before: " + hookName + " at " + entryHook.getEntryPoint() +
                " noReturn=" + entryHook.hasNoReturn());
            if (entryHook.hasNoReturn()) {
                entryHook.setNoReturn(false);
            }
            println("entry hook after: " + hookName +
                " noReturn=" + entryHook.hasNoReturn());
            commit = true;
        }
        finally {
            currentProgram.endTransaction(transaction, commit);
        }

        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("decompiler could not open current program");
            }
            DecompileResults result = decompiler.decompileFunction(target, 120, monitor);
            if (!result.decompileCompleted()) {
                throw new IllegalStateException("decompilation failed: " + result.getErrorMessage());
            }
            try (BufferedWriter writer = Files.newBufferedWriter(
                     outputPath, StandardCharsets.UTF_8,
                     StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                writer.write("Ghidra function: " + target.getEntryPoint() + "\n");
                writer.write("Target: " + targetName + "\n\n");
                writer.write(result.getDecompiledFunction().getC());
                writer.write("\n");
            }
            println("wrote pseudocode to " + outputPath);
        }
        finally {
            decompiler.dispose();
        }
    }
}
