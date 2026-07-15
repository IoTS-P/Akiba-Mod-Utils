// @name: search_strings
// @author: Akiba
// @description: Search defined strings by substring (case-insensitive by default) and return their addresses. If query is empty, list all defined strings.
// @parameters: query (string) - Substring to search for inside string values. Empty string lists all defined strings; caseSensitive (boolean, optional) - Match case-sensitively (default: false); exact (boolean, optional) - Require full-string equality instead of substring (default: false, ignored when query is empty); minLength (integer, optional) - Minimum string length to consider (default: 1); limit (integer, optional) - Max results to return (default: 200)

import org.iotsplab.akiba.script.AkibaScript

class SearchStrings : AkibaScript() {
    override suspend fun execute() {
        val query = scriptArgs["query"] as? String
            ?: run { appendLine("Error: 'query' parameter is required (use empty string to list all strings)"); return }
        val listAll = query.isEmpty()

        val caseSensitive = (scriptArgs["caseSensitive"] as? Boolean) ?: false
        val exact = (scriptArgs["exact"] as? Boolean) ?: false
        val minLength = (scriptArgs["minLength"] as? Number)?.toInt() ?: 1
        val limit = (scriptArgs["limit"] as? Number)?.toInt() ?: 200

        val needle = if (caseSensitive) query else query.lowercase()

        val listing = program!!.listing
        val iter = listing.getDefinedData(true)

        var matched = 0
        var scanned = 0
        var truncated = false

        if (listAll) {
            appendLine("Listing all defined strings (minLength=$minLength, limit=$limit)")
        } else {
            appendLine(
                "Searching strings for ${if (exact) "exact match" else "substring"} " +
                    "\"${query.take(120)}\" (caseSensitive=$caseSensitive, minLength=$minLength, limit=$limit)"
            )
        }
        appendLine("")

        while (iter.hasNext()) {
            val data = iter.next()
            if (!data.hasStringValue()) continue
            val value = data.value?.toString() ?: continue
            if (value.length < minLength) continue
            scanned++

            val hit = if (listAll) {
                true
            } else {
                val haystack = if (caseSensitive) value else value.lowercase()
                if (exact) haystack == needle else haystack.contains(needle)
            }
            if (!hit) continue

            if (matched >= limit) {
                truncated = true
                break
            }

            // Truncate long string previews for output readability.
            val preview = value.replace("\n", "\\n").replace("\r", "\\r").take(200)
            appendLine("${data.address}: \"$preview\"")
            matched++
        }

        appendLine("")
        appendLine("Matched: $matched / scanned: $scanned" + if (truncated) " (truncated at limit=$limit)" else "")
        if (matched == 0) {
            appendLine("")
            appendLine("Hint: only DEFINED strings are searched. If a string isn't found, it may not be auto-analyzed yet, or its encoding differs.")
        } else {
            appendLine("")
            appendLine("Next step: pass one of the addresses above to 'get_xrefs' (target=<address>) to find references to that specific string.")
        }
    }
}
