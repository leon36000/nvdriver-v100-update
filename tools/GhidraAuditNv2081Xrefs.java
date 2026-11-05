// Bounded read-only Ghidra audit for unresolved REA xref sources.
// Run with analyzeHeadless -import <ET_REL> -postScript GhidraAuditNv2081Xrefs.java.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class GhidraAuditNv2081Xrefs extends GhidraScript {
    private static final String[] DEFAULT_SOURCES = {
        "0x6caeb95", "0x6caebb0", "0x6caee23", "0x6cafe00"
    };

    @Override
    public void run() throws Exception {
        println("program=" + currentProgram.getName());
        println("language=" + currentProgram.getLanguageID());
        println("imageBase=" + currentProgram.getImageBase());
        println("memoryBlocks:");
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            println("  name=" + block.getName()
                + " start=" + block.getStart()
                + " end=" + block.getEnd()
                + " size=0x" + Long.toHexString(block.getSize())
                + " initialized=" + block.isInitialized()
                + " read=" + block.isRead()
                + " write=" + block.isWrite()
                + " execute=" + block.isExecute()
                + " source=" + block.getSourceName());
        }

        Symbol targetSymbol = null;
        SymbolIterator named = currentProgram.getSymbolTable().getSymbols("_nv020818rm");
        while (named.hasNext()) {
            Symbol s = named.next();
            if (s.getName().equals("_nv020818rm")) {
                targetSymbol = s;
                break;
            }
        }
        if (targetSymbol == null) {
            println("targetSymbol=missing");
        } else {
            Address target = targetSymbol.getAddress();
            Function f = currentProgram.getFunctionManager().getFunctionAt(target);
            println("targetSymbol=" + targetSymbol.getName()
                + " address=" + target
                + " symbolType=" + targetSymbol.getSymbolType()
                + " function=" + (f == null ? "missing" : f.getName())
                + " functionBody=" + (f == null ? "missing" : f.getBody()));
            printReferencesTo(target, "target-entry");
            if (f != null) {
                for (Address a : f.getBody().getAddresses(true)) {
                    printReferencesTo(a, "target-body");
                }
            }
        }

        String[] sources = getScriptArgs().length == 0 ? DEFAULT_SOURCES : getScriptArgs();
        for (String text : sources) {
            Address a;
            try {
                a = toAddr(text);
            } catch (Exception e) {
                println("source=" + text + " parseError=" + e.getMessage());
                continue;
            }
            MemoryBlock block = currentProgram.getMemory().getBlock(a);
            Instruction instruction = currentProgram.getListing().getInstructionContaining(a);
            CodeUnit unit = currentProgram.getListing().getCodeUnitContaining(a);
            println("source=" + a
                + " memoryBlock=" + (block == null ? "none" : block.getName())
                + " instruction=" + (instruction == null ? "none" : instruction.toString())
                + " instructionAddress=" + (instruction == null ? "none" : instruction.getAddress())
                + " codeUnit=" + (unit == null ? "none" : unit.getClass().getSimpleName()));
            for (Symbol s : currentProgram.getSymbolTable().getSymbols(a)) {
                println("  sourceSymbol=" + s.getName() + " type=" + s.getSymbolType());
            }
            for (Reference ref : currentProgram.getReferenceManager().getReferencesFrom(a)) {
                println("  outgoingRef=" + ref.getReferenceType()
                    + " operand=" + ref.getOperandIndex()
                    + " to=" + ref.getToAddress()
                    + " primary=" + ref.isPrimary());
            }
            for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(a)) {
                println("  incomingRef=" + ref.getReferenceType()
                    + " operand=" + ref.getOperandIndex()
                    + " from=" + ref.getFromAddress()
                    + " primary=" + ref.isPrimary());
            }
        }
    }

    private void printReferencesTo(Address address, String label) {
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(address);
        while (refs.hasNext()) {
            Reference ref = refs.next();
            println(label + " ref=" + ref.getReferenceType()
                + " from=" + ref.getFromAddress()
                + " to=" + ref.getToAddress()
                + " operand=" + ref.getOperandIndex()
                + " primary=" + ref.isPrimary());
        }
    }
}
