// @name: write_memory
// @author: Akiba
// @description: Write data to program memory at a specified address. Supports multiple data formats: raw bytes (hex string), 8-bit / 16-bit / 32-bit / 64-bit integer arrays, and strings. Each write is limited to 256 bytes. Writes that cross memory block boundaries or fall outside mapped memory are rejected. The original (pre-modification) byte values are displayed in the output for audit; full write history is recoverable from the script execution database and the saved original binary.
// @parameters: address (string) - Start address to write to (hex, e.g. "0x401000"); format (string, optional) - Data format: "bytes" (hex string, default), "u8"/"int8" (JSON array of byte values 0-255), "int16"/"u16" (JSON array of 16-bit values), "int32"/"u32" (JSON array of 32-bit values), "int64"/"u64" (JSON array of 64-bit values), "string" (plain text); data (string or array, required) - The data to write. For "bytes": a hex string like "deadbeef" or "de ad be ef" (separators are stripped). For integer arrays: a JSON array like [1,2,3] or a JSON string "[1,2,3]". For "string": the text to write; endian (string, optional) - Byte order for integer formats: "little", "big", or "program" (default: "program"); charset (string, optional) - Character encoding for "string" format (default: "UTF-8"); size (integer, optional) - Expected write size in bytes for validation — must match the data size. Maximum 256 bytes per call.
// @dedup: args_only

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.mem.MemoryAccessException
import java.nio.charset.Charset

class WriteMemory : AkibaScript() {
    companion object {
        private const val MAX_WRITE_SIZE = 256
    }

    override suspend fun execute() {
        val addressStr = scriptArgs["address"] as? String
            ?: run { appendLine("Error: 'address' parameter is required"); return }
        val format = ((scriptArgs["format"] as? String) ?: "bytes").lowercase()
        val dataArg = scriptArgs["data"]
            ?: run { appendLine("Error: 'data' parameter is required"); return }

        // ── Parse address ────────────────────────────────────────────────
        val start = try { program.addressFactory.getAddress(addressStr) }
            catch (_: Exception) { null }
            ?: run { appendLine("Error: invalid address '$addressStr'"); return }

        // ── Determine endianness ─────────────────────────────────────────
        val bigEndian = when (((scriptArgs["endian"] as? String) ?: "program").lowercase()) {
            "big", "be" -> true
            "little", "le" -> false
            else -> program.language.isBigEndian
        }

        // ── Convert data to byte array based on format ───────────────────
        val bytes: ByteArray = try {
            when (format) {
                "bytes", "hex" -> parseHexBytes(dataArg)
                "u8", "int8", "uint8", "byte" -> parseIntArray(dataArg, 1, bigEndian)
                "int16", "u16", "uint16", "short" -> parseIntArray(dataArg, 2, bigEndian)
                "int32", "u32", "uint32", "int" -> parseIntArray(dataArg, 4, bigEndian)
                "int64", "u64", "uint64", "long" -> parseIntArray(dataArg, 8, bigEndian)
                "string", "str" -> {
                    val charsetName = (scriptArgs["charset"] as? String) ?: "UTF-8"
                    (dataArg as? String ?: dataArg.toString()).toByteArray(Charset.forName(charsetName))
                }
                else -> {
                    appendLine("Error: unsupported format '$format'")
                    appendLine("  Supported: bytes, u8/int8, int16/u16, int32/u32, int64/u64, string")
                    return
                }
            }
        } catch (e: IllegalArgumentException) {
            appendLine("Error: ${e.message}")
            return
        }

        if (bytes.isEmpty()) {
            appendLine("Error: data is empty — nothing to write")
            return
        }

        // ── Optional size validation ─────────────────────────────────────
        val expectedSize = (scriptArgs["size"] as? Number)?.toInt()
        if (expectedSize != null && expectedSize != bytes.size) {
            appendLine("Error: 'size' ($expectedSize) does not match data size (${bytes.size})")
            return
        }

        // ── Enforce max write size (256 bytes) ───────────────────────────
        if (bytes.size > MAX_WRITE_SIZE) {
            appendLine("Error: write size ${bytes.size} exceeds maximum of $MAX_WRITE_SIZE bytes")
            appendLine("  Split the write into multiple calls of <= $MAX_WRITE_SIZE bytes each.")
            return
        }

        // ── Validate memory range is inside a single mapped block ────────
        val block = program.memory.getBlock(start)
        if (block == null) {
            appendLine("Error: address $start is not inside any memory block")
            appendLine("  Use list_memory_segments to see all available blocks.")
            return
        }
        val end = try { start.add(bytes.size.toLong() - 1) } catch (_: Exception) { null }
        if (end == null || !block.contains(end)) {
            appendLine("Error: write range $start + ${bytes.size} bytes crosses block boundary or exceeds mapped memory")
            appendLine("  Block: ${block.name} ${block.start}-${block.end} (${block.size} bytes)")
            appendLine("  Use list_memory_segments to see all available blocks.")
            return
        }

        // ── Read original bytes (for display / audit) ────────────────────
        val originalBytes = ByteArray(bytes.size)
        try {
            program.memory.getBytes(start, originalBytes)
        } catch (e: MemoryAccessException) {
            appendLine("Error: failed to read original bytes at $start: ${e.message}")
            return
        }

        val oldHex = originalBytes.joinToString(" ") { "%02x".format(it.toInt() and 0xff) }
        val newHex = bytes.joinToString(" ") { "%02x".format(it.toInt() and 0xff) }
        val oldAscii = toAsciiDump(originalBytes)
        val newAscii = toAsciiDump(bytes)

        appendLine("=== Write Memory ===")
        appendLine("Address: $start - $end (${bytes.size} bytes)")
        appendLine("Block: ${block.name} ${perms(block)}")
        appendLine("Format: $format  endian=${if (bigEndian) "big" else "little"}")
        appendLine("")
        appendLine("Before: $oldHex  |$oldAscii|")
        appendLine("After:  $newHex  |$newAscii|")
        appendLine("")

        // ── Write in a transaction ───────────────────────────────────────
        val txId = program.startTransaction("write_memory @ $start (${bytes.size} bytes)")
        var committed = false
        try {
            program.memory.setBytes(start, bytes)
            committed = true
        } catch (e: Exception) {
            appendLine("Error: write failed: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            program.endTransaction(txId, committed)
        }

        if (!committed) return

        // ── Verify the write by reading back ─────────────────────────────
        val readBack = ByteArray(bytes.size)
        var verifyOk = false
        try {
            program.memory.getBytes(start, readBack)
            verifyOk = readBack.contentEquals(bytes)
        } catch (_: Exception) { }

        appendLine("")
        appendLine("Write successful: ${bytes.size} bytes written to $start")
        appendLine("  Old: $oldHex")
        appendLine("  New: $newHex")
        if (verifyOk) {
            appendLine("  Verification: read-back matches written data.")
        } else {
            appendLine("  Warning: read-back verification failed — the memory may not have been updated as expected.")
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /**
     * Parse a hex string into a byte array. Strips common separators
     * (spaces, commas, colons, semicolons) and optional 0x prefixes.
     */
    private fun parseHexBytes(data: Any): ByteArray {
        val hexStr = (data as? String ?: data.toString()).trim()
        val cleaned = hexStr
            .replace("0x", "", ignoreCase = true)
            .replace(Regex("[\\s,;:]"), "")
        if (cleaned.isEmpty()) {
            throw IllegalArgumentException("hex byte string is empty after cleaning")
        }
        if (cleaned.length % 2 != 0) {
            throw IllegalArgumentException(
                "hex string has odd length (${cleaned.length} chars) — each byte needs 2 hex digits")
        }
        if (!cleaned.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
            throw IllegalArgumentException("hex string contains non-hex characters: $cleaned")
        }
        return cleaned.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    /**
     * Parse a JSON array of integers into a byte array with the given
     * unit size (1, 2, 4, or 8 bytes per element), encoded with the
     * specified endianness.
     */
    @Suppress("UNCHECKED_CAST")
    private fun parseIntArray(data: Any, unitSize: Int, bigEndian: Boolean): ByteArray {
        val list: List<Any?> = when (data) {
            is List<*> -> data
            is String -> try {
                com.fasterxml.jackson.databind.ObjectMapper()
                    .readValue(data, List::class.java) as List<Any?>
            } catch (e: Exception) {
                throw IllegalArgumentException("'data' is not a valid JSON array: ${e.message}")
            }
            else -> throw IllegalArgumentException(
                "'data' for integer formats must be a JSON array or JSON string, got ${data.javaClass.simpleName}")
        }
        if (list.isEmpty()) {
            throw IllegalArgumentException("integer array is empty")
        }
        val result = ByteArray(list.size * unitSize)
        for ((i, item) in list.withIndex()) {
            val value: Long = when (item) {
                is Number -> item.toLong()
                is String -> {
                    val s = item.trim()
                    if (s.startsWith("0x", ignoreCase = true) || s.startsWith("-0x", ignoreCase = true)) {
                        val neg = s.startsWith("-")
                        val hexPart = s.substring(if (neg) 3 else 2)
                        val v = hexPart.toLongOrNull(16)
                            ?: throw IllegalArgumentException("invalid hex value '$item' at index $i")
                        if (neg) -v else v
                    } else {
                        s.toLongOrNull()
                            ?: throw IllegalArgumentException("invalid integer value '$item' at index $i")
                    }
                }
                else -> throw IllegalArgumentException(
                    "invalid value at index $i: $item (expected number)")
            }
            // Validate value fits in the unit size (unsigned for sizes < 8)
            if (unitSize < 8) {
                val maxVal = (1L shl (unitSize * 8)) - 1
                if (value < 0 || value > maxVal) {
                    throw IllegalArgumentException(
                        "value $value at index $i does not fit in unsigned $unitSize-byte range (0..$maxVal)")
                }
            }
            // Encode to bytes
            val off = i * unitSize
            if (bigEndian) {
                for (b in 0 until unitSize) {
                    result[off + b] = ((value shr ((unitSize - 1 - b) * 8)) and 0xFF).toByte()
                }
            } else {
                for (b in 0 until unitSize) {
                    result[off + b] = ((value shr (b * 8)) and 0xFF).toByte()
                }
            }
        }
        return result
    }

    private fun toAsciiDump(bytes: ByteArray): String {
        return bytes.joinToString("") {
            val c = it.toInt() and 0xff; if (c in 32..126) c.toChar().toString() else "."
        }
    }

    private fun perms(block: ghidra.program.model.mem.MemoryBlock): String {
        return "" + (if (block.isRead) "r" else "-") +
               (if (block.isWrite) "w" else "-") +
               (if (block.isExecute) "x" else "-")
    }
}
