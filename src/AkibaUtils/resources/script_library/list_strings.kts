// @name: list_strings
// @author: Akiba
// @description: List all defined strings in the binary with their addresses and values
// @parameters: minLength (integer, optional) - Minimum string length to include (default: 4)

import org.iotsplab.akiba.script.AkibaScript

class ListStrings : AkibaScript() {
    override suspend fun execute() {
        val minLength = (scriptArgs["minLength"] as? Number)?.toInt() ?: 4

        val listing = currentProgram!!.listing
        val iter = listing.getDefinedData(true)
        var count = 0

        while (iter.hasNext()) {
            val data = iter.next()
            if (data.hasStringValue()) {
                val value = data.value?.toString() ?: continue
                if (value.length >= minLength) {
                    appendLine("${data.address}: \"${value.take(200)}\"")
                    count++
                }
            }
        }

        appendLine("\nTotal: $count strings (minLength=$minLength)")
    }
}
