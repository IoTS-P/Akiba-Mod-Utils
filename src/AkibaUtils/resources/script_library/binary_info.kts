// @name: binary_info
// @author: Akiba
// @description: Display comprehensive information about the loaded binary (format, architecture, entry point, sections, imports, exports)
// @parameters: none

import org.iotsplab.akiba.script.AkibaScript

class BinaryInfo : AkibaScript() {
    override suspend fun execute() {
        val prog = program!!

        appendLine("=== Binary Information ===")
        appendLine("Name:        ${prog.name}")
        appendLine("Format:      ${prog.executableFormat}")
        appendLine("Language:    ${prog.languageID}")
        appendLine("Compiler:    ${prog.compiler}")
        appendLine("Address Size: ${prog.defaultPointerSize * 8}-bit")
        appendLine("Image Base:  ${prog.imageBase}")
        appendLine("Min Address: ${prog.minAddress}")
        appendLine("Max Address: ${prog.maxAddress}")
        appendLine("")

        // Memory blocks (sections)
        appendLine("=== Memory Blocks ===")
        val blocks = prog.memory.blocks
        appendLine(String.format("  %-20s %-12s %-10s %s", "Name", "Start", "Size", "Permissions"))
        blocks.forEach { block ->
            val perms = buildString {
                if (block.isRead) append("R")
                if (block.isWrite) append("W")
                if (block.isExecute) append("X")
            }
            appendLine(String.format("  %-20s %-12s %-10s %s",
                block.name, block.start, "${block.size} bytes", perms))
        }
        appendLine("")

        // Function count
        val fm = prog.functionManager
        val funcCount = fm.functionCount
        appendLine("=== Functions ===")
        appendLine("Total: $funcCount functions")
        appendLine("")

        // Entry points
        val symbolTable = prog.symbolTable
        appendLine("=== Entry Points ===")
        val entryFuncs = symbolTable.getExternalEntryPointIterator()
        var entryCount = 0
        while (entryFuncs.hasNext() && entryCount < 10) {
            val addr = entryFuncs.next()
            val func = fm.getFunctionAt(addr)
            appendLine("  ${func?.name ?: "?"} @ $addr")
            entryCount++
        }
        if (entryCount == 0) appendLine("  (none found)")
        appendLine("")

        // Imports (external functions)
        appendLine("=== Imports (External Functions) ===")
        val extFuncs = fm.getExternalFunctions()
        var importCount = 0
        while (extFuncs.hasNext() && importCount < 50) {
            val func = extFuncs.next()
            appendLine("  ${func.name}")
            importCount++
        }
        if (importCount == 0) appendLine("  (none)")
        else if (importCount >= 50) appendLine("  ... (showing first 50)")
    }
}
