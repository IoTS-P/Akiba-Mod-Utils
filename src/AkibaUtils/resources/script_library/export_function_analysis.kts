// @name: export_function_analysis
// @author: Akiba
// @description: Export a complete analysis package for a function: full disassembly, decompiled C code, and statement-level mapping between C and assembly. The package is saved to the workspace directory (functions/<addr>_<name>/ by default). Designed for analyzing long functions whose disassembly cannot fit in a single tool call result.
// @parameters: target (string, required) - Function name or hex address (e.g. "main" or "0x401000"); address (string, optional) - Alias for target; function (string, optional) - Alias for target; function_name (string, optional) - Alias for target; outputDir (string, optional) - Relative path within the workspace for the functions directory (default: "functions"); decompileTimeout (integer, optional) - Decompilation timeout in seconds (default 120, max 600). Increase for very large functions (e.g. 10000+ instructions).
// @dedup: args_only

import org.iotsplab.akiba.script.AkibaScript
import ghidra.app.decompiler.ClangStatement
import ghidra.app.decompiler.ClangTokenGroup
import ghidra.app.decompiler.ClangToken
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.CommentType
import ghidra.program.model.pcode.PcodeOp
import org.iotsplab.akiba.utils.highFunction.getCCodeStructure
import org.iotsplab.akiba.utils.highFunction.getCCode
import org.iotsplab.akiba.utils.highFunction.allStatements
import java.io.File

class ExportFunctionAnalysis : AkibaScript() {
    override suspend fun execute() {
        val program = this.program!!
        val fm = program.functionManager

        // ── Resolve target function ──
        val targetStr = (scriptArgs["target"] ?: scriptArgs["address"]
            ?: scriptArgs["function"] ?: scriptArgs["function_name"])
            ?.toString()
            ?: run { appendLine("Error: 'target' (or 'address'/'function'/'function_name') parameter is required"); return }

        var func: Function? = null
        // Try by name first.
        val iter = fm.getFunctions(true)
        while (iter.hasNext()) {
            val f = iter.next()
            if (f.name.equals(targetStr, ignoreCase = true)) { func = f; break }
        }
        // Try as address.
        if (func == null) {
            val addr = try { program.addressFactory.getAddress(targetStr) } catch (_: Exception) { null }
            if (addr != null) {
                func = fm.getFunctionAt(addr) ?: fm.getFunctionContaining(addr)
            }
        }
        if (func == null) {
            appendLine("Error: Function '$targetStr' not found")
            return
        }

        // ── Determine output directory ──
        val outputDirName = (scriptArgs["outputDir"] as? String)?.takeIf { it.isNotBlank() } ?: "functions"
        // Use the caller's workspace directory (injected as _akiba_workspace_dir
        // by ScriptLibraryTool), not the script's own workspaceDir (which is
        // under id=-1/ExportFunctionAnalysis/).
        val wsRoot = (scriptArgs["_akiba_workspace_dir"] as? String)?.let { File(it) }
            ?: workspaceDir.toFile()
        val functionsDir = File(wsRoot, outputDirName)
        if (!functionsDir.exists()) functionsDir.mkdirs()

        // Sanitise function name for directory use.
        val entryAddr = func.entryPoint.toString()
        val safeName = func.name.replace(Regex("[^a-zA-Z0-9._-]"), "_")
        val dirName = "${entryAddr}_${safeName}"
        val funcDir = File(functionsDir, dirName)
        if (!funcDir.exists()) funcDir.mkdirs()

        appendLine("Exporting analysis package for: ${func.name} @ ${func.entryPoint}")
        appendLine("Output directory: ${funcDir.relativeTo(wsRoot)}")
        appendLine("")

        // ── 1. Export full disassembly ──
        val disasmFile = File(funcDir, "disasm.txt")
        val disasmBuilder = StringBuilder()
        val listing = program.listing
        val insnIter = listing.getInstructions(func.body, true)
        var instrCount = 0
        val addrToIndex = mutableMapOf<String, Int>()  // address → 1-based index

        disasmBuilder.appendLine("; Function: ${func.name} @ ${func.entryPoint}")
        disasmBuilder.appendLine("; Body: ${func.body.minAddress} - ${func.body.maxAddress}")
        disasmBuilder.appendLine("")

        while (insnIter.hasNext()) {
            val insn = insnIter.next()
            instrCount++
            val addrStr = insn.address.toString()
            addrToIndex[addrStr] = instrCount

            // PLATE comment (AKIBA: note)
            insn.getComment(CommentType.PLATE)?.lineSequence()?.forEach { line ->
                disasmBuilder.appendLine("    ; $line")
            }

            val bytesStr = try {
                insn.bytes.joinToString(" ") { "%02x".format(it.toInt() and 0xff) }.padEnd(24)
            } catch (_: Exception) { "".padEnd(24) }

            val asm = insn.toString()
            val eol = insn.getComment(CommentType.EOL)?.let { "  ; $it" } ?: ""

            disasmBuilder.appendLine("$addrStr  $bytesStr  $asm$eol")
        }

        disasmFile.writeText(disasmBuilder.toString())
        appendLine("- disasm.txt: $instrCount instructions")

        // ── 2. Export decompiled C code ──
        // For very large functions (10000+ instructions), the default 120s
        // timeout may not be enough. The LLM can pass a larger value via
        // the 'decompileTimeout' parameter.
        val decompileTimeout = ((scriptArgs["decompileTimeout"] as? Number)?.toInt() ?: 120)
            .coerceIn(10, 600)
        val cCode = try { func.getCCode(decompileTimeout) } catch (e: Exception) {
            appendLine("Error: decompilation failed: ${e.message}")
            if (e is IllegalStateException && e.message?.contains("within") == true) {
                appendLine("  This is likely a TIMEOUT. The function has $instrCount instructions,")
                appendLine("  which may exceed the ${decompileTimeout}s decompilation budget.")
                appendLine("  Re-run with a larger decompileTimeout (e.g. 300 or 600).")
            }
            "// Decompilation failed: ${e.message}\n"
        }
        val decompFile = File(funcDir, "decomp.c")
        decompFile.writeText(cCode)
        appendLine("- decomp.c: ${cCode.lines().size} lines")

        // ── 3. Build C-to-assembly mapping ──
        val mappingFile = File(funcDir, "mapping.json")
        val mappingBuilder = StringBuilder()
        mappingBuilder.appendLine("{")
        mappingBuilder.appendLine("  \"function\": \"${escapeJson(func.name)} @ ${func.entryPoint}\",")
        mappingBuilder.appendLine("  \"entryAddress\": \"${escapeJson(entryAddr)}\",")
        mappingBuilder.appendLine("  \"totalInstructions\": $instrCount,")
        mappingBuilder.appendLine("  \"totalCLines\": ${cCode.lines().size},")
        mappingBuilder.appendLine("  \"statements\": [")

        val cCodeStructure = try { func.getCCodeStructure(decompileTimeout) } catch (_: Exception) { null }
        if (cCodeStructure != null) {
            val statements = cCodeStructure.allStatements()
            statements.forEachIndexed { i, stmt ->
                val cText = stmt.toString().trim()
                val minAddr = stmt.minAddress
                val maxAddr = stmt.maxAddress
                val pcodeOp = stmt.pcodeOp
                val rootAddr = pcodeOp?.seqnum?.target

                // Collect all instruction addresses in [minAddr, maxAddr]
                val asmAddrs = mutableListOf<String>()
                val asmIndices = mutableListOf<Int>()
                if (minAddr != null && maxAddr != null) {
                    val addrIter = listing.getInstructions(minAddr, true)
                    while (addrIter.hasNext()) {
                        val insn = addrIter.next()
                        if (insn.address > maxAddr) break
                        val a = insn.address.toString()
                        asmAddrs.add(a)
                        addrToIndex[a]?.let { asmIndices.add(it) }
                    }
                }

                // Also include the root PcodeOp address if it's outside [min, max]
                if (rootAddr != null) {
                    val rootAddrStr = rootAddr.toString()
                    if (rootAddrStr !in asmAddrs) {
                        asmAddrs.add(0, rootAddrStr)  // prepend as the primary address
                        addrToIndex[rootAddrStr]?.let { asmIndices.add(0, it) }
                    }
                }

                val asmRange = if (minAddr != null && maxAddr != null) {
                    "$minAddr-$maxAddr"
                } else "null"

                mappingBuilder.appendLine("    {")
                mappingBuilder.appendLine("      \"index\": $i,")
                mappingBuilder.appendLine("      \"cText\": \"${escapeJson(cText)}\",")
                mappingBuilder.appendLine("      \"asmRange\": \"${escapeJson(asmRange)}\",")
                mappingBuilder.appendLine("      \"asmAddrs\": [${asmAddrs.joinToString(",") { "\"${escapeJson(it)}\"" }}],")
                mappingBuilder.appendLine("      \"asmIndices\": [${asmIndices.joinToString(",")}],")
                if (rootAddr != null) {
                    mappingBuilder.appendLine("      \"rootAddr\": \"${escapeJson(rootAddr.toString())}\"")
                } else {
                    mappingBuilder.appendLine("      \"rootAddr\": null")
                }
                if (i < statements.size - 1) {
                    mappingBuilder.appendLine("    },")
                } else {
                    mappingBuilder.appendLine("    }")
                }
            }
        }

        mappingBuilder.appendLine("  ]")
        mappingBuilder.appendLine("}")
        mappingFile.writeText(mappingBuilder.toString())
        val stmtCount = cCodeStructure?.allStatements()?.size ?: 0
        appendLine("- mapping.json: $stmtCount statement-level mappings")

        // ── 4. Export function metadata ──
        val metaFile = File(funcDir, "meta.json")
        val paramsStr = func.parameters.joinToString(", ") { p ->
            "${p.dataType?.name ?: "void*"} ${p.name ?: "param"}"
        }
        val metaBuilder = StringBuilder()
        metaBuilder.appendLine("{")
        metaBuilder.appendLine("  \"name\": \"${escapeJson(func.name)}\",")
        metaBuilder.appendLine("  \"entryAddress\": \"${escapeJson(entryAddr)}\",")
        metaBuilder.appendLine("  \"bodyRange\": \"${func.body.minAddress}-${func.body.maxAddress}\",")
        metaBuilder.appendLine("  \"bodySize\": ${func.body.numAddresses},")
        metaBuilder.appendLine("  \"instructionCount\": $instrCount,")
        metaBuilder.appendLine("  \"returnType\": \"${escapeJson(func.returnType?.name ?: "void")}\",")
        metaBuilder.appendLine("  \"parameters\": \"$paramsStr\",")
        metaBuilder.appendLine("  \"isThunk\": ${func.isThunk},")
        metaBuilder.appendLine("  \"isExternal\": ${func.isExternal},")
        metaBuilder.appendLine("  \"callingConvention\": \"${escapeJson(func.callingConventionName ?: "unknown")}\"")
        metaBuilder.appendLine("}")
        metaFile.writeText(metaBuilder.toString())
        appendLine("- meta.json: function metadata")

        appendLine("")
        appendLine("Analysis package exported to: ${funcDir.relativeTo(wsRoot)}")
        appendLine("Use read_workspace_file to read decomp.c (full pseudo-C code),")
        appendLine("disasm.txt (full disassembly), and mapping.json (C↔assembly mapping).")
        appendLine("For large functions, start by reading decomp.c, then use mapping.json")
        appendLine("to locate specific assembly addresses for verification.")
    }

    private fun escapeJson(s: String): String {
        return s.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
    }
}

// Re-export the allStatements extension so the script can use it.
// This is already available via the import of ClangTokenGroup extensions.
