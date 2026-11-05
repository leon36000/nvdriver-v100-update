// Emit bounded function/reference metadata for one address; never emit reconstructed code.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class GhidraLocateFunctionAtAddress extends GhidraScript {
    private static final String PREFIX = "GHIDRA_RESULT:";
    private static final int MAX_REFERENCES = 64;

    private static class Records {
        private final List<String> json = new ArrayList<String>();
        private boolean truncated;

        private void add(String value) {
            if (json.size() == MAX_REFERENCES) {
                truncated = true;
                return;
            }
            json.add(value);
        }

        private String asJson() {
            Collections.sort(json);
            return "[" + String.join(",", json) + "]";
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 8) {
            throw new IllegalArgumentException("expected one to eight image-relative RVAs");
        }
        List<Long> targets = new ArrayList<Long>();
        for (String arg : args) {
            long rva = Long.decode(arg);
            if (rva < 0) throw new IllegalArgumentException("RVA must be nonnegative");
            if (targets.contains(rva)) throw new IllegalArgumentException("duplicate RVA");
            targets.add(rva);
        }
        for (Long rva : targets) analyzeRva(rva.longValue());
    }

    private void analyzeRva(long rva) throws Exception {
        if (rva < 0) throw new IllegalArgumentException("RVA must be nonnegative");
        Address imageBase = currentProgram.getImageBase();
        Address target = imageBase.add(rva);
        Function function = currentProgram.getFunctionManager().getFunctionContaining(target);
        if (function == null || !function.getBody().contains(target)) {
            emitNoFunction(rva, imageBase, target);
            return;
        }

        Listing listing = currentProgram.getListing();
        int instructionCount = 0;
        for (Instruction ignored : listing.getInstructions(function.getBody(), true)) {
            instructionCount++;
            if (instructionCount > 10_000_000) {
                throw new IllegalStateException("function instruction count exceeded bound");
            }
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        DecompileResults decompileResults;
        try {
            decompileResults = decompiler.decompileFunction(function, 90, monitor);
        } finally {
            decompiler.dispose();
        }
        boolean decompilerCompleted = decompileResults != null
            && decompileResults.decompileCompleted();
        Address entry = function.getEntryPoint();
        long endExclusive = function.getBody().getMaxAddress().getOffset() + 1;
        Records incoming = incomingCallers(function, imageBase);
        Records outgoing = outgoingCalls(function, imageBase);

        String json = "{"
            + "\"schema\":\"nvidia-hybrid-ghidra-function-at-rva-v2\","
            + "\"status\":\"function_found\","
            + "\"target_rva\":\"0x" + Long.toHexString(rva) + "\","
            + "\"image_base\":\"0x" + Long.toHexString(imageBase.getOffset()) + "\","
            + "\"target_address\":\"0x" + Long.toHexString(target.getOffset()) + "\","
            + "\"function_name\":\"" + escapeJson(function.getName()) + "\","
            + "\"function_entry\":\"0x" + Long.toHexString(entry.getOffset()) + "\","
            + "\"function_end_exclusive\":\"0x" + Long.toHexString(endExclusive) + "\","
            + "\"instruction_count\":" + instructionCount + ","
            + "\"decompiler_completed\":" + decompilerCompleted + ","
            + "\"incoming_callers\":" + incoming.asJson() + ","
            + "\"incoming_callers_truncated\":" + incoming.truncated + ","
            + "\"outgoing_calls\":" + outgoing.asJson() + ","
            + "\"outgoing_calls_truncated\":" + outgoing.truncated
            + "}";
        println(PREFIX + json);
    }

    private Records incomingCallers(Function target, Address imageBase) {
        Records records = new Records();
        ReferenceIterator references = currentProgram.getReferenceManager()
            .getReferencesTo(target.getEntryPoint());
        while (references.hasNext()) {
            Reference reference = references.next();
            if (!reference.getReferenceType().isCall()) continue;
            Address source = reference.getFromAddress();
            String sourceRva = relativeRva(source, imageBase);
            if (sourceRva == null) continue;
            Function caller = currentProgram.getFunctionManager().getFunctionContaining(source);
            String callerName = caller == null ? "unresolved" : caller.getName();
            String callerEntry = caller == null ? "null"
                : quote(relativeRva(caller.getEntryPoint(), imageBase));
            records.add("{\"source_rva\":" + quote(sourceRva)
                + ",\"source_function_name\":" + quote(callerName)
                + ",\"source_function_entry_rva\":" + callerEntry
                + ",\"reference_type\":" + quote(reference.getReferenceType().toString()) + "}");
        }
        return records;
    }

    private Records outgoingCalls(Function target, Address imageBase) {
        Records records = new Records();
        for (Instruction instruction : currentProgram.getListing()
                .getInstructions(target.getBody(), true)) {
            Reference[] references = currentProgram.getReferenceManager()
                .getReferencesFrom(instruction.getAddress());
            for (Reference reference : references) {
                if (!reference.getReferenceType().isCall()) continue;
                Address destination = reference.getToAddress();
                String targetRva = relativeRva(destination, imageBase);
                Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(destination);
                String targetName = symbol == null ? "unresolved" : symbol.getName();
                boolean external = !destination.getAddressSpace().equals(imageBase.getAddressSpace())
                    || currentProgram.getMemory().getBlock(destination) == null;
                records.add("{\"source_rva\":"
                    + quote(relativeRva(instruction.getAddress(), imageBase))
                    + ",\"target_name\":" + quote(targetName)
                    + ",\"target_rva\":" + quote(targetRva)
                    + ",\"target_external\":" + external
                    + ",\"reference_type\":" + quote(reference.getReferenceType().toString()) + "}");
            }
        }
        return records;
    }

    private String relativeRva(Address address, Address imageBase) {
        if (address == null || !address.getAddressSpace().equals(imageBase.getAddressSpace())
                || address.getOffset() < imageBase.getOffset()) return null;
        return "0x" + Long.toHexString(address.getOffset() - imageBase.getOffset());
    }

    private String quote(String value) {
        return value == null ? "null" : "\"" + escapeJson(value) + "\"";
    }

    private void emitNoFunction(long rva, Address imageBase, Address target) {
        println(PREFIX + "{"
            + "\"schema\":\"nvidia-hybrid-ghidra-function-at-rva-v2\","
            + "\"status\":\"function_missing\","
            + "\"target_rva\":\"0x" + Long.toHexString(rva) + "\","
            + "\"image_base\":\"0x" + Long.toHexString(imageBase.getOffset()) + "\","
            + "\"target_address\":\"0x" + Long.toHexString(target.getOffset()) + "\"}"
        );
    }

    private String escapeJson(String text) {
        StringBuilder escaped = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '"' || c == '\\') escaped.append('\\').append(c);
            else if (c >= 0x20) escaped.append(c);
            else escaped.append(String.format("\\u%04x", (int) c));
        }
        return escaped.toString();
    }
}
