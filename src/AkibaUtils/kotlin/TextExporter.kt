package org.iotsplab.akiba.module

import ghidra.app.decompiler.DecompInterface
import ghidra.base.project.GhidraProject
import ghidra.framework.model.DomainFile
import ghidra.framework.model.DomainFolder
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Listing
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.CommentType
import ghidra.util.task.ConsoleTaskMonitor
import org.apache.logging.log4j.Logger
import java.nio.file.Files
import java.nio.file.Path
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper

// ============================================================
//  Text Export Renderer — runs inside AkibaUtils module
//
//  Renders per-program text (listing, comments, data, decompiled
//  C, function metadata) to the module workspace directory.  The
//  framework collects the workspace contents and zips them.
// ============================================================

private val exportMapper = jacksonObjectMapper()
    .enable(com.fasterxml.jackson.databind.SerializationFeature.INDENT_OUTPUT)

/** Marker object for program consumer release. */
private object TextExportConsumer

/**
 * Render a full project text export into [outputDir].
 *
 * Iterates every program-domain-file in the project, opens it, and
 * writes per-program text files under `programs/<name>/`.
 * Also writes `index.md`, `manifest.json`, and `README.md` at the
 * output-dir root.
 *
 * @param project      The open [GhidraProject].
 * @param projectName  Human-readable project name (for manifest/index).
 * @param config       Export options from the module config.
 * @param outputDir    Destination directory (cleaned before writing).
 * @param logger       Logger for diagnostic messages.
 */
fun exportProjectText(
    project: GhidraProject,
    projectName: String,
    config: TextExportConfig,
    outputDir: Path,
    logger: Logger,
) {
    val opts = resolveOptions(config)
    val exportedAt = java.time.Instant.now().toString()
    val warnings = mutableListOf<String>()

    // Clean and recreate the output directory
    if (Files.exists(outputDir)) {
        outputDir.toFile().deleteRecursively()
    }
    Files.createDirectories(outputDir)

    // Force-refresh the project data index from disk so programs
    // added by other processes are visible.
    try {
        project.projectData.refresh(true)
    } catch (e: Exception) {
        logger.warn("[text-export] projectData.refresh() failed: ${e.message}")
    }

    val programs = collectDomainFiles(project.projectData.rootFolder)
    logger.info("[text-export] project='$projectName' domainFiles=${programs.size}")

    if (programs.isEmpty()) {
        logger.warn("[text-export] project '$projectName' has 0 domain files.")
        warnings += "Project root folder contains 0 domain files — the opened project appears to be empty."
    }

    val programFilterRegex = opts.programFilter
    val programMeta = mutableListOf<Map<String, Any?>>()

    for (domainFile in programs) {
        // Optional program-name filter
        if (programFilterRegex != null && !programFilterRegex.containsMatchIn(domainFile.name)) {
            continue
        }

        val program = tryOpenProgram(project, domainFile, logger) ?: run {
            warnings += "Skipped non-program or unreadable domain file: ${domainFile.pathname}"
            continue
        }
        try {
            val safeProgramName = safeSegment(program.name)
            val prefix = outputDir.resolve("programs").resolve(safeProgramName)
            Files.createDirectories(prefix)

            val functions = selectFunctions(program, opts)
            programMeta += mapOf(
                "name" to program.name,
                "path" to domainFile.pathname,
                "language" to program.languageID.toString(),
                "compiler" to program.compilerSpec.compilerSpecID.toString(),
                "imageBase" to hex(program.imageBase.offset),
                "functions" to functions.size,
            )
            writeJson(prefix, "meta.json", mapOf(
                "name" to program.name,
                "path" to domainFile.pathname,
                "language" to program.languageID.toString(),
                "compiler" to program.compilerSpec.compilerSpecID.toString(),
                "imageBase" to hex(program.imageBase.offset),
            ))
            if ("functions" in opts.contents) {
                writeJson(prefix, "functions.json", mapOf(
                    "program" to program.name,
                    "functions" to functions.map { fn ->
                        mapOf(
                            "name" to fn.name,
                            "entryPoint" to hex(fn.entryPoint.offset),
                            "size" to fn.body.numAddresses,
                            "skippedBySize" to (fn.body.numAddresses > opts.maxFunctionSize),
                        )
                    }
                ))
            }
            if ("listing" in opts.contents) {
                writeText(prefix, "listing.md", renderListing(program, functions, opts))
            }
            if ("comments" in opts.contents && opts.includeComments) {
                writeText(prefix, "comments.txt", renderComments(program, functions, opts))
            }
            if ("data" in opts.contents && opts.includeData) {
                writeText(prefix, "data.txt", renderData(program, functions, opts))
            }
            if (opts.includeDecompile && "decompile" in opts.contents) {
                writeText(prefix, "decompiled.c", renderDecompile(program, functions, opts, warnings))
            }
        } catch (e: Exception) {
            logger.warn("[text-export] failed to render '${domainFile.pathname}': ${e.message}", e)
            warnings += "Render failed for ${domainFile.pathname}: ${e.message}"
        } finally {
            // Release the program back to the project.  GhidraProject.
            // openProgram() registers the project itself as the consumer,
            // so we must release via project.close() rather than
            // program.release(arbitraryConsumer).
            try {
                project.close(program)
            } catch (e: Exception) {
                logger.warn("[text-export] failed to close program '${domainFile.pathname}': ${e.message}")
            }
        }
    }

    // Root-level files
    writeText(outputDir, "index.md", buildString {
        appendLine("# $projectName — Akiba text export")
        appendLine()
        appendLine("- Exported: $exportedAt")
        appendLine("- Programs: ${programMeta.size}")
        appendLine("- Contents: ${opts.contents.sorted()}")
        appendLine()
        appendLine("## Programs")
        appendLine()
        programMeta.forEach { p ->
            appendLine("- `${p["path"]}` — `${p["language"]}` (${p["functions"]} functions)")
        }
    })
    writeJson(outputDir, "manifest.json", mapOf(
        "project" to projectName,
        "exportedAt" to exportedAt,
        "releasedAfterExport" to true,
        "contents" to opts.contents.sorted(),
        "programs" to programMeta,
        "warnings" to warnings,
    ))
    writeText(outputDir, "README.md", "Generated by Akiba text export. Files are organized under programs/<program>/.")
}

// ---- Internal resolved options -----------------------------------------

private data class ResolvedOptions(
    val contents: Set<String>,
    val includeComments: Boolean,
    val includeEolComment: Boolean,
    val includePlateComment: Boolean,
    val includePreComment: Boolean,
    val includePostComment: Boolean,
    val includeRepeatableComment: Boolean,
    val includeDecompile: Boolean,
    val decompileTimeoutSec: Int,
    val includeData: Boolean,
    val includeUndefined: Boolean,
    val functionFilter: Regex?,
    val addressFilter: AddressRange?,
    val maxFunctions: Int,
    val maxFunctionSize: Int,
    val sortBy: String,
    val programFilter: Regex?,
)

private data class AddressRange(val start: String, val end: String)

private fun resolveOptions(config: TextExportConfig): ResolvedOptions {
    val contents = config.contents.map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet()
    val sortBy = config.sortBy.lowercase()
    val functionFilter = config.functionFilter?.takeIf { it.isNotBlank() }?.let {
        try { Regex(it) } catch (_: Exception) { null }
    }
    val programFilter = config.programFilter?.takeIf { it.isNotBlank() }?.let {
        try { Regex(it) } catch (_: Exception) { null }
    }
    val addressFilter = config.addressFilter?.let {
        AddressRange(it.start, it.end)
    }
    return ResolvedOptions(
        contents = contents,
        includeComments = config.includeComments,
        includeEolComment = config.includeEolComment,
        includePlateComment = config.includePlateComment,
        includePreComment = config.includePreComment,
        includePostComment = config.includePostComment,
        includeRepeatableComment = config.includeRepeatableComment,
        includeDecompile = config.includeDecompile,
        decompileTimeoutSec = config.decompileTimeoutSec.coerceIn(1, 600),
        includeData = config.includeData,
        includeUndefined = config.includeUndefined,
        functionFilter = functionFilter,
        addressFilter = addressFilter,
        maxFunctions = config.maxFunctions.coerceAtLeast(0),
        maxFunctionSize = config.maxFunctionSize.coerceAtLeast(1),
        sortBy = sortBy,
        programFilter = programFilter,
    )
}

// ---- Domain file iteration ---------------------------------------------

private fun collectDomainFiles(folder: DomainFolder): List<DomainFile> {
    val out = mutableListOf<DomainFile>()
    out += folder.files.toList()
    folder.folders.forEach { out += collectDomainFiles(it) }
    return out
}

private fun tryOpenProgram(
    project: GhidraProject,
    domainFile: DomainFile,
    logger: Logger,
): Program? = try {
    // domainObjectClass returns the concrete implementation (e.g.
    // ghidra.program.database.ProgramDB), not the Program interface.
    // Use isAssignableFrom so any Program implementation passes.
    val doc = domainFile.domainObjectClass
    if (doc == null || !Program::class.java.isAssignableFrom(doc)) {
        logger.info("[text-export] skipping non-program file '${domainFile.pathname}' (class=${doc?.name})")
        return null
    }
    project.openProgram(domainFile.parent.pathname, domainFile.name, true)
} catch (e: Exception) {
    logger.warn(
        "[text-export] failed to open domain file '${domainFile.pathname}' " +
            "(class=${domainFile.domainObjectClass?.simpleName}): " +
            "${e.javaClass.simpleName}: ${e.message}"
    )
    null
}

// ---- Function selection -------------------------------------------------

private fun selectFunctions(program: Program, opts: ResolvedOptions): List<Function> {
    var functions = program.functionManager.getFunctions(true).toList()
    opts.functionFilter?.let { rx -> functions = functions.filter { rx.containsMatchIn(it.name) } }
    opts.addressFilter?.let { af ->
        val start = program.addressFactory.getAddress(af.start)
            ?: throw IllegalArgumentException("Invalid addressFilter.start: ${af.start}")
        val end = program.addressFactory.getAddress(af.end)
            ?: throw IllegalArgumentException("Invalid addressFilter.end: ${af.end}")
        require(start <= end) { "addressFilter.start must be <= addressFilter.end" }
        val range = AddressSet(start, end)
        functions = functions.filter { range.contains(it.entryPoint) }
    }
    functions = when (opts.sortBy) {
        "name" -> functions.sortedBy { it.name }
        "size" -> functions.sortedByDescending { it.body.numAddresses }
        else -> functions.sortedBy { it.entryPoint.offset }
    }
    return if (opts.maxFunctions > 0) functions.take(opts.maxFunctions) else functions
}

// ---- Renderers ----------------------------------------------------------

private fun renderListing(program: Program, functions: List<Function>, opts: ResolvedOptions): String {
    val listing = program.listing
    return buildString {
        appendLine("# Listing — ${program.name}")
        appendLine()
        for (fn in functions) {
            appendLine("## ${fn.name} @ ${hex(fn.entryPoint.offset)} (${fn.body.numAddresses} bytes)")
            appendLine()
            appendFunctionHeaderComments(this, listing, fn, opts)
            if (fn.body.numAddresses > opts.maxFunctionSize) {
                appendLine("_Skipped: function body exceeds maxFunctionSize=${opts.maxFunctionSize}_")
                appendLine()
                continue
            }
            appendLine("```asm")
            val it = listing.getInstructions(fn.body, true)
            while (it.hasNext()) {
                val insn = it.next()
                append(hex(insn.minAddress.offset)).append("  ").append(insn.toString())
                if (opts.includeComments && opts.includeEolComment) {
                    val c = insn.getComment(CommentType.EOL)
                    if (!c.isNullOrBlank()) append("  ; ").append(c.replace('\n', ' '))
                }
                appendLine()
            }
            appendLine("```")
            appendLine()
        }
    }
}

private fun appendFunctionHeaderComments(
    sb: StringBuilder,
    listing: Listing,
    fn: Function,
    opts: ResolvedOptions,
) {
    if (!opts.includeComments) return
    val comments = listOfNotNull(
        if (opts.includePlateComment) "Plate" to listing.getComment(CommentType.PLATE, fn.entryPoint) else null,
        if (opts.includePreComment) "Pre" to listing.getComment(CommentType.PRE, fn.entryPoint) else null,
        if (opts.includePostComment) "Post" to listing.getComment(CommentType.POST, fn.entryPoint) else null,
        if (opts.includeRepeatableComment) "Repeatable" to listing.getComment(CommentType.REPEATABLE, fn.entryPoint) else null,
    ).filter { !it.second.isNullOrBlank() }
    for ((label, comment) in comments) {
        sb.appendLine("**$label comment:**")
        sb.appendLine()
        sb.appendLine("```")
        sb.appendLine(comment!!.trim())
        sb.appendLine("```")
        sb.appendLine()
    }
}

private fun renderComments(program: Program, functions: List<Function>, opts: ResolvedOptions): String {
    val listing = program.listing
    return buildString {
        for (fn in functions) {
            val before = length
            appendLine("# ${fn.name} @ ${hex(fn.entryPoint.offset)}")
            appendFunctionHeaderComments(this, listing, fn, opts)
            if (opts.includeEolComment) {
                val it = listing.getInstructions(fn.body, true)
                while (it.hasNext()) {
                    val insn = it.next()
                    val c = insn.getComment(CommentType.EOL)
                    if (!c.isNullOrBlank()) {
                        appendLine("${hex(insn.minAddress.offset)}: ${c.replace('\n', ' ')}")
                    }
                }
            }
            if (length == before + "# ${fn.name} @ ${hex(fn.entryPoint.offset)}\n".length) {
                setLength(before)
            } else {
                appendLine()
            }
        }
    }
}

private fun renderData(program: Program, functions: List<Function>, opts: ResolvedOptions): String {
    val listing = program.listing
    return buildString {
        for (fn in functions) {
            if (fn.body.numAddresses > opts.maxFunctionSize) continue
            val it = listing.getDefinedData(fn.body, true)
            var wroteHeader = false
            while (it.hasNext()) {
                val data = it.next()
                val type = data.dataType.name
                if (!opts.includeUndefined && type == "undefined") continue
                if (!wroteHeader) {
                    appendLine("# ${fn.name} @ ${hex(fn.entryPoint.offset)}")
                    wroteHeader = true
                }
                appendLine("${hex(data.minAddress.offset)}  $type")
            }
            if (wroteHeader) appendLine()
        }
    }
}

private fun renderDecompile(
    program: Program,
    functions: List<Function>,
    opts: ResolvedOptions,
    warnings: MutableList<String>,
): String {
    val monitor = ConsoleTaskMonitor()
    val decompiler = DecompInterface()
    return try {
        decompiler.openProgram(program)
        buildString {
            for (fn in functions) {
                if (fn.body.numAddresses > opts.maxFunctionSize) continue
                val result = decompiler.decompileFunction(fn, opts.decompileTimeoutSec, monitor)
                if (result != null && result.decompileCompleted()) {
                    val c = result.getDecompiledFunction()?.getC()
                    if (!c.isNullOrBlank()) {
                        appendLine("/* ---- ${fn.name} @ ${hex(fn.entryPoint.offset)} ---- */")
                        appendLine(c.trim())
                        appendLine()
                    }
                } else {
                    warnings += "Decompile failed for ${program.name}/${fn.name}: ${result?.errorMessage ?: "unknown"}"
                }
            }
        }
    } finally {
        decompiler.dispose()
    }
}

// ---- File helpers -------------------------------------------------------

private fun writeText(dir: Path, name: String, text: String) {
    Files.writeString(dir.resolve(name), text)
}

private fun writeJson(dir: Path, name: String, payload: Any) {
    writeText(dir, name, exportMapper.writeValueAsString(payload))
}

private fun safeSegment(value: String): String =
    value.replace(Regex("[^A-Za-z0-9._-]+"), "_").take(64).ifBlank { "unnamed" }

private fun hex(offset: Long): String = "0x${offset.toString(16)}"
