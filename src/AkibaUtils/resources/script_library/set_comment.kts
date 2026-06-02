// @name: set_comment
// @author: Akiba
// @description: Add or update a comment at a listing address. Supports all five Ghidra comment types (EOL, PRE, POST, PLATE, REPEATABLE) via the new CommentType API. Pass an empty string to clear the comment.
// @parameters: address (string) - Hex address where the comment will be attached (e.g. "0x401000"); type (string, optional) - One of "EOL", "PRE", "POST", "PLATE", "REPEATABLE" (default: "EOL", case-insensitive); comment (string) - Comment text. Empty string clears the existing comment of that type; append (boolean, optional) - If true and a comment of this type already exists, append the new text on a new line instead of replacing (default: false)

import org.iotsplab.akiba.script.AkibaScript
import ghidra.program.model.listing.CommentType

class SetComment : AkibaScript() {
    override suspend fun execute() {
        val addressStr = scriptArgs["address"] as? String
            ?: run { appendLine("Error: 'address' parameter is required"); return }
        val typeStr = (scriptArgs["type"] as? String)?.uppercase() ?: "EOL"
        val comment = scriptArgs["comment"] as? String
            ?: run { appendLine("Error: 'comment' parameter is required (use \"\" to clear)"); return }
        val append = (scriptArgs["append"] as? Boolean) ?: false

        // Map the user-friendly string to the new CommentType enum. We accept
        // the short names ("EOL"/"PRE"/...) as well as the legacy *_COMMENT
        // suffix to be forgiving of muscle memory.
        val commentType = when (typeStr.removeSuffix("_COMMENT")) {
            "EOL" -> CommentType.EOL
            "PRE" -> CommentType.PRE
            "POST" -> CommentType.POST
            "PLATE" -> CommentType.PLATE
            "REPEATABLE" -> CommentType.REPEATABLE
            else -> {
                appendLine("Error: invalid comment type '$typeStr'. Expected one of: EOL, PRE, POST, PLATE, REPEATABLE.")
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

        val existing = listing.getComment(commentType, address)
        val newValue = when {
            comment.isEmpty() -> null  // explicit clear
            append && !existing.isNullOrEmpty() -> "$existing\n$comment"
            else -> comment
        }

        // Comment writes mutate the program DB and therefore require an open
        // transaction. The script runner does not wrap us in one, so we open
        // and commit our own here. The transaction is rolled back on failure.
        val txId = program.startTransaction("set_comment ($commentType @ $address)")
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
