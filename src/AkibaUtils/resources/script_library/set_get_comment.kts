// @name: set_get_comment
// @author: Akiba
// @description: Add, update, clear, or read comments at a listing address. Supports all five Ghidra comment types (EOL, PRE, POST, PLATE, REPEATABLE) via the new CommentType API. Pass action="read" to inspect comments; pass an empty string to clear the selected comment type.
// @parameters: address (string) - Hex address where the comment is attached (e.g. "0x401000"); action (string, optional) - "set" or "read" (default: "set"); type (string, optional) - One of "EOL", "PRE", "POST", "PLATE", "REPEATABLE", or "ALL" for read mode (default: "EOL", case-insensitive); comment (string, required for action=set) - Comment text. Empty string clears the existing comment of that type; append (boolean, optional) - If true and a comment of this type already exists, append the new text on a new line instead of replacing (default: false)

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.listing.CommentType

class SetGetComment : AkibaScript() {
    override suspend fun execute() {
        val addressStr = scriptArgs["address"] as? String
            ?: run { appendLine("Error: 'address' parameter is required"); return }
        val action = ((scriptArgs["action"] as? String) ?: "set").lowercase()
        val typeStr = (scriptArgs["type"] as? String)?.uppercase() ?: "EOL"
        val append = (scriptArgs["append"] as? Boolean) ?: false

        // Map the user-friendly string to the new CommentType enum. We accept
        // the short names ("EOL"/"PRE"/...) as well as the legacy *_COMMENT
        // suffix to be forgiving of muscle memory. In read mode, type=ALL reads
        // all supported comment types at the address.
        val normalizedType = typeStr.removeSuffix("_COMMENT")
        val commentType = when (normalizedType) {
            "EOL" -> CommentType.EOL
            "PRE" -> CommentType.PRE
            "POST" -> CommentType.POST
            "PLATE" -> CommentType.PLATE
            "REPEATABLE" -> CommentType.REPEATABLE
            "ALL" -> null
            else -> {
                appendLine("Error: invalid comment type '$typeStr'. Expected one of: EOL, PRE, POST, PLATE, REPEATABLE, ALL.")
                return
            }
        }

        val program = currentProgram!!
        val address = try {
            program.addressFactory.getAddress(addressStr)
        } catch (_: Exception) { null }
        if (address == null) {
            appendLine("Error: cannot parse address '$addressStr'")
            return
        }

        val listing = program.listing
        val codeUnit = listing.getCodeUnitAt(address) ?: listing.getCodeUnitContaining(address)
        if (codeUnit == null) {
            appendLine("Warning: no code unit at $address — comment will still be attached to the address.")
        }

        if (action == "read") {
            val typesToRead = if (commentType == null) {
                listOf(CommentType.EOL, CommentType.PRE, CommentType.POST, CommentType.PLATE, CommentType.REPEATABLE)
            } else {
                listOf(commentType)
            }
            appendLine("Comments at $address:")
            var found = false
            for (t in typesToRead) {
                val value = listing.getComment(t, address)
                appendLine("- $t: " + if (value == null) "<none>" else value.replace("\n", "\\n"))
                if (value != null) found = true
            }
            if (!found) appendLine("No comments found at $address for requested type(s).")
            return
        }

        if (action != "set") {
            appendLine("Error: invalid action '$action'. Expected 'set' or 'read'.")
            return
        }
        if (commentType == null) {
            appendLine("Error: type=ALL is only valid for action=read.")
            return
        }

        val comment = scriptArgs["comment"] as? String
            ?: run { appendLine("Error: 'comment' parameter is required for action=set (use \"\" to clear)"); return }
        val existing = listing.getComment(commentType, address)
        val newValue = when {
            comment.isEmpty() -> null  // explicit clear
            append && !existing.isNullOrEmpty() -> "$existing\n$comment"
            else -> comment
        }

        // Comment writes mutate the program DB and therefore require an open
        // transaction. The script runner does not wrap us in one, so we open
        // and commit our own here. The transaction is rolled back on failure.
        val txId = program.startTransaction("set_get_comment ($commentType @ $address)")
        var ok = false
        try {
            listing.setComment(address, commentType, newValue)
            ok = true
        } catch (e: Exception) {
            appendLine("Error: setComment failed: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            program.endTransaction(txId, ok)
        }

        if (!ok) return

        when {
            newValue == null -> appendLine("Cleared $commentType comment at $address")
            existing == null -> appendLine("Set $commentType comment at $address")
            append -> appendLine("Appended to existing $commentType comment at $address")
            else -> appendLine("Replaced existing $commentType comment at $address")
        }

        // Echo the final comment back so the caller can verify the result.
        val finalValue = listing.getComment(commentType, address)
        if (finalValue != null) {
            appendLine("")
            appendLine("Current $commentType comment:")
            finalValue.lineSequence().forEach { appendLine("  $it") }
        }
    }
}
