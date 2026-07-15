// @name: search_memory
// @author: Akiba
// @description: Search program memory for patterns. Two modes: (1) regex — search for strings matching a regular expression using RegexSearcher, which handles overlap removal and conflict filtering across all initialized memory; (2) bytes — search for an exact byte sequence specified as a hex string. If both 'pattern' and 'bytes' are provided, 'pattern' (regex) takes precedence.
// @parameters: pattern (string, optional) - Regex pattern for string search (e.g., "password|secret", "[A-Z][a-z]+"). Uses RegexSearcher to search all initialized memory. The regex is applied to the raw byte content; bytes (string, optional) - Hex string for exact byte search, e.g., "deadbeef" or "de ad be ef" (separators are stripped). Each byte is converted to a \\xNN regex escape for exact matching; limit (integer, optional) - Maximum results to return (default: 200); contextBytes (integer, optional) - In bytes mode, number of context bytes to show on each side of a match (default: 16); clearOverlap (boolean, optional) - In regex mode, remove overlapping matches (default: true); clearConflict (boolean, optional) - In regex mode, remove matches that conflict with defined data/code (default: true)
// @dedup: args_only

import org.iotsplab.akiba.script.AkibaScript
import org.iotsplab.akiba.utils.string.RegexSearcher
import org.iotsplab.akiba.utils.string.StringSearchResult
import ghidra.features.base.memsearch.bytesource.AddressableByteSource
import ghidra.features.base.memsearch.bytesource.ProgramByteSource
import ghidra.features.base.memsearch.format.SearchFormat
import ghidra.features.base.memsearch.gui.SearchSettings
import ghidra.features.base.memsearch.matcher.RegExByteMatcher
import ghidra.features.base.memsearch.matcher.SearchData
import ghidra.features.base.memsearch.searcher.MemoryMatch
import ghidra.features.base.memsearch.searcher.MemorySearcher
import ghidra.util.datastruct.ListAccumulator
import java.util.regex.Pattern

class SearchMemory : AkibaScript() {
    companion object {
        private const val DEFAULT_LIMIT = 200
        private const val DEFAULT_CONTEXT_BYTES = 16
        private const val MAX_SEARCH_RESULTS = 10000
    }

    override suspend fun execute() {

        val patternStr = scriptArgs["pattern"] as? String
        val bytesStr = scriptArgs["bytes"] as? String

        if (patternStr.isNullOrBlank() && bytesStr.isNullOrBlank()) {
            appendLine("Error: either 'pattern' (regex string search) or 'bytes' (hex byte search) parameter is required")
            return
        }

        val limit = ((scriptArgs["limit"] as? Number)?.toInt() ?: DEFAULT_LIMIT).coerceAtLeast(1)
        val contextBytes = ((scriptArgs["contextBytes"] as? Number)?.toInt() ?: DEFAULT_CONTEXT_BYTES).coerceIn(0, 256)

        if (!patternStr.isNullOrBlank()) {
            searchRegex(program, patternStr, limit)
        } else {
            searchBytes(program, bytesStr!!, limit, contextBytes)
        }
    }

    // ── Regex string search using RegexSearcher ──────────────────────────

    private fun searchRegex(
        program: ghidra.program.model.listing.Program,
        patternStr: String,
        limit: Int
    ) {
        val clearOverlap = (scriptArgs["clearOverlap"] as? Boolean) ?: true
        val clearConflict = (scriptArgs["clearConflict"] as? Boolean) ?: true

        val pattern = try {
            Pattern.compile(patternStr)
        } catch (e: Exception) {
            appendLine("Error: invalid regex pattern '$patternStr': ${e.message}")
            return
        }

        appendLine("=== Memory Search (Regex) ===")
        appendLine("Pattern: $patternStr")
        appendLine("Overlap removal: $clearOverlap")
        appendLine("Conflict removal: $clearConflict")
        appendLine("")

        val searcher = RegexSearcher(program, pattern, clearOverlap, clearConflict)
        val results: List<StringSearchResult> = try {
            searcher.search()
        } catch (e: Exception) {
            appendLine("Error: search failed: ${e.javaClass.simpleName}: ${e.message}")
            return
        }

        if (results.isEmpty()) {
            appendLine("No matches found.")
            return
        }

        appendLine("Found ${results.size} match(es), showing first ${minOf(limit, results.size)}:")
        appendLine("")

        for (result in results.take(limit)) {
            val preview = result.value
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .take(200)
            appendLine("${result.address}: \"$preview\"")
        }

        if (results.size > limit) {
            appendLine("")
            appendLine("... (${results.size - limit} more matches, increase 'limit' to see more)")
        }

        appendLine("")
        appendLine("Total: ${results.size} match(es)")
    }

    // ── Exact byte search using MemorySearcher ───────────────────────────

    private fun searchBytes(
        program: ghidra.program.model.listing.Program,
        bytesStr: String,
        limit: Int,
        contextBytes: Int
    ) {
        // Parse hex string to bytes
        val cleaned = bytesStr.trim()
            .replace("0x", "", ignoreCase = true)
            .replace(Regex("[\\s,;:]"), "")

        if (cleaned.isEmpty()) {
            appendLine("Error: hex byte string is empty after cleaning")
            return
        }
        if (cleaned.length % 2 != 0) {
            appendLine("Error: hex string has odd length (${cleaned.length} chars) — each byte needs 2 hex digits")
            return
        }
        if (!cleaned.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
            appendLine("Error: hex string contains non-hex characters: $cleaned")
            return
        }

        val searchBytes = cleaned.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        // Convert each byte to \xNN regex escape for exact matching.
        // In the regex string, \\xNN matches the byte with value 0xNN.
        val regexPattern = searchBytes.joinToString("") {
            "\\x%02x".format(it.toInt() and 0xff)
        }

        appendLine("=== Memory Search (Bytes) ===")
        appendLine("Pattern: ${searchBytes.joinToString(" ") { "%02x".format(it.toInt() and 0xff) }}")
        appendLine("Length: ${searchBytes.size} byte(s)")
        appendLine("Context: $contextBytes byte(s) on each side")
        appendLine("")

        val byteSource: AddressableByteSource = ProgramByteSource(program)
        val matcher = RegExByteMatcher(
            regexPattern,
            SearchSettings().withSearchFormat(SearchFormat.REG_EX)
        )
        val searcher = MemorySearcher(
            byteSource, matcher,
            program.memory.allInitializedAddressSet,
            MAX_SEARCH_RESULTS
        )

        val results = ListAccumulator<MemoryMatch<SearchData>>()
        try {
            searcher.findAll(results, taskGlobalMonitor)
        } catch (e: Exception) {
            appendLine("Error: search failed: ${e.javaClass.simpleName}: ${e.message}")
            return
        }

        val matches = results.asList()

        if (matches.isEmpty()) {
            appendLine("No matches found.")
            return
        }

        appendLine("Found ${matches.size} match(es), showing first ${minOf(limit, matches.size)}:")
        appendLine("")

        for (match in matches.take(limit)) {
            val addr = match.address
            val matchLen = match.length
            val block = program.memory.getBlock(addr)
            val blockName = block?.name ?: "?"

            // Read context bytes
            val ctxBefore = readContextBytes(program, addr, -contextBytes, contextBytes)
            val matchBytes = readContextBytes(program, addr, 0, matchLen)
            val ctxAfter = readContextBytes(program, addr, matchLen, contextBytes)

            val beforeHex = ctxBefore.joinToString(" ") { "%02x".format(it.toInt() and 0xff) }
            val matchHex = matchBytes.joinToString(" ") { "%02x".format(it.toInt() and 0xff) }
            val afterHex = ctxAfter.joinToString(" ") { "%02x".format(it.toInt() and 0xff) }

            val beforeAscii = toAsciiDump(ctxBefore)
            val matchAscii = toAsciiDump(matchBytes)
            val afterAscii = toAsciiDump(ctxAfter)

            appendLine("$addr  [$blockName]  $matchLen byte(s)")
            appendLine("  Hex:   ...$beforeHex [$matchHex] $afterHex...")
            appendLine("  ASCII: ...$beforeAscii [$matchAscii] $afterAscii...")
        }

        if (matches.size > limit) {
            appendLine("")
            appendLine("... (${matches.size - limit} more matches, increase 'limit' to see more)")
        }

        appendLine("")
        appendLine("Total: ${matches.size} match(es)")
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private fun readContextBytes(
        program: ghidra.program.model.listing.Program,
        addr: ghidra.program.model.address.Address,
        offset: Int,
        length: Int
    ): ByteArray {
        if (length <= 0) return ByteArray(0)
        val readAddr = try {
            if (offset >= 0) addr.add(offset.toLong())
            else addr.subtract((-offset).toLong())
        } catch (_: Exception) { return ByteArray(0) }

        val block = program.memory.getBlock(readAddr) ?: return ByteArray(0)
        val endAddr = try { readAddr.add(length.toLong() - 1) } catch (_: Exception) { return ByteArray(0) }
        if (!block.contains(endAddr)) return ByteArray(0)

        val result = ByteArray(length)
        try {
            program.memory.getBytes(readAddr, result)
        } catch (_: Exception) {
            return ByteArray(length)
        }
        return result
    }

    private fun toAsciiDump(bytes: ByteArray): String {
        return bytes.joinToString("") {
            val c = it.toInt() and 0xff; if (c in 32..126) c.toChar().toString() else "."
        }
    }
}
