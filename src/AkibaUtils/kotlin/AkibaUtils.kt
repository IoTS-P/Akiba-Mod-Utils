package org.iotsplab.akiba.module

import org.iotsplab.akiba.data.database.AgentDatabaseClient
import org.iotsplab.akiba.managers.BinaryMetadata
import org.iotsplab.akiba.utils.DoNotCreateTable
import org.iotsplab.akiba.utils.ProcedureArgumentsDeserializer
import org.iotsplab.akiba.utils.highFunction.getCCode
import java.util.jar.JarFile

@DoNotCreateTable
class AkibaUtils: AkibaModule() {

    override suspend fun startProcess() {
        logger.info("AkibaUtils: Seeding preset scripts into script library...")
        seedPresetScripts()
        logger.info("AkibaUtils: Script library seeding complete.")
    }

    /**
     * Load preset scripts from the module JAR (via [extractFileInJar] pattern)
     * and save them to the `scripts` table with the "library:" prefix.
     * Uses the duplicate-check logic in DB Daemon (same author → overwrite).
     */
    private fun seedPresetScripts() {
        val agentDbClient = AgentDatabaseClient(dbClient)
        val knownScripts = listOf(
            "script_library/binary_info.kts",
            "script_library/list_functions.kts",
            "script_library/decompile_function.kts",
            "script_library/find_dangerous_calls.kts",
            "script_library/list_strings.kts",
            "script_library/get_xrefs.kts",
            "script_library/search_strings.kts",
            "script_library/disassemble_function.kts",
            "script_library/set_comment.kts"
        )

        val moduleJarPath = ProcedureArgumentsDeserializer.allModules[this::class.qualifiedName]
        if (moduleJarPath == null) {
            logger.warn("AkibaUtils: cannot locate module JAR, skipping script seeding")
            return
        }

        JarFile(moduleJarPath.toFile()).use { jar ->
            for (entryPath in knownScripts) {
                val entry = jar.getEntry(entryPath)
                if (entry == null) {
                    logger.warn("AkibaUtils: $entryPath not found in JAR")
                    continue
                }

                val source = jar.getInputStream(entry).bufferedReader(Charsets.UTF_8).use { it.readText() }
                val fileName = entryPath.substringAfterLast("/")
                val meta = parseScriptMeta(source, fileName) ?: continue

                try {
                    agentDbClient.createScript(
                        name = meta.name,
                        description = meta.description,
                        author = "Akiba",
                        code = source,
                        language = "kotlin",
                        saveResult = true,
                        maxOutputSize = 10 * 1024 * 1024
                    )
                    logger.info("AkibaUtils: seeded script '${meta.name}'")
                } catch (e: Exception) {
                    logger.warn("AkibaUtils: failed to seed script '${meta.name}': ${e.message}")
                }
            }
        }
    }

    /**
     * Parse metadata annotations from script source header comments.
     */
    private fun parseScriptMeta(source: String, fileName: String): ScriptMeta? {
        var name = fileName.removeSuffix(".kts")
        var description = ""

        for (line in source.lines()) {
            val trimmed = line.trim()
            if (!trimmed.startsWith("//")) break

            when {
                trimmed.startsWith("// @name:") ->
                    name = trimmed.removePrefix("// @name:").trim()
                trimmed.startsWith("// @description:") ->
                    description = trimmed.removePrefix("// @description:").trim()
            }
        }

        return ScriptMeta(name, description)
    }

    private data class ScriptMeta(val name: String, val description: String)
}