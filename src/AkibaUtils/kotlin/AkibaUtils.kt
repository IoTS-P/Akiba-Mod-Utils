package org.iotsplab.akiba.module

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.iotsplab.akiba.data.database.AgentDatabaseClient
import org.iotsplab.akiba.llm.agent.AgentModule
import org.iotsplab.akiba.llm.agent.akibaAgent
import org.iotsplab.akiba.llm.memory.persistentChatMemory
import org.iotsplab.akiba.llm.skill.SkillManager
import org.iotsplab.akiba.llm.tool.BuiltInTools
import org.iotsplab.akiba.managers.ConfigManager
import org.iotsplab.akiba.utils.DoNotCreateTable
import org.iotsplab.akiba.utils.ProcedureArgumentsDeserializer
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.time.Duration
import java.util.Comparator
import java.util.jar.JarFile

@DoNotCreateTable
class AkibaUtils: AgentModule() {

    override fun taskPrompt(): String = ""

    override suspend fun startProcess() {
        if (scriptSeeded) return
        logger.info("AkibaUtils: Seeding preset scripts into script library...")
        seedPresetScripts()
        logger.info("AkibaUtils: Script library seeding complete.")
        logger.info("AkibaUtils: Installing bundled skills...")
        installBundledSkills()
        logger.info("AkibaUtils: Bundled skill installation complete.")
        scriptSeeded = true

        if (System.getenv("AKIBA_MANUAL_AGENT") == "1") {
            logger.info("AkibaUtils: manual agent worker mode detected")
            runManualAgentTurn()
        }
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
            "script_library/set_get_comment.kts",
            "script_library/entry_point_context.kts",
            "script_library/read_memory_region.kts",
            "script_library/elf_plt_got_info.kts",
            "script_library/list_memory_segments.kts",
            "script_library/rename_function.kts",
            "script_library/create_data_type.kts",
            "script_library/change_variable_type.kts",
            "script_library/define_undefine_data.kts",
            "script_library/rename_label.kts"
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

    /** Install bundled skills from this module JAR into the target skill namespace. */
    private fun installBundledSkills(username: String = "akiba") {
        val moduleJarPath = ProcedureArgumentsDeserializer.allModules[this::class.qualifiedName]
        if (moduleJarPath == null) {
            logger.warn("AkibaUtils: cannot locate module JAR, skipping bundled skill installation")
            return
        }
        val skillPrefixes = listOf("skills/binary-vuln-audit/")
        JarFile(moduleJarPath.toFile()).use { jar ->
            for (prefix in skillPrefixes) {
                val tmp = Files.createTempDirectory("akiba_bundled_skill_")
                try {
                    var copied = false
                    val entries = jar.entries()
                    while (entries.hasMoreElements()) {
                        val entry = entries.nextElement()
                        if (entry.isDirectory || !entry.name.startsWith(prefix)) continue
                        val rel = entry.name.removePrefix(prefix)
                        if (rel.isBlank()) continue
                        val out = tmp.resolve(rel).normalize()
                        Files.createDirectories(out.parent)
                        jar.getInputStream(entry).use { input ->
                            Files.newOutputStream(out).use { output -> input.copyTo(output) }
                        }
                        copied = true
                    }
                    if (!copied) {
                        logger.warn("AkibaUtils: bundled skill resource '$prefix' not found in JAR")
                        continue
                    }
                    val installed = SkillManager.installSkillDirectory(username, tmp)
                    logger.info("AkibaUtils: installed bundled skill '${installed.id}' for user '$username'")
                } catch (e: Exception) {
                    logger.warn("AkibaUtils: failed to install bundled skill '$prefix': ${e.message}")
                } finally {
                    runCatching { Files.walk(tmp).use { stream ->
                        stream.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
                    } }
                }
            }
        }
    }

    /**
     * Parse metadata annotations from script source header comments.
     */
    private fun runManualAgentTurn() {
        val start = requestManualAgentStart()
        installBundledSkills(start.username)
        val agentDbClient = AgentDatabaseClient(dbClient)
        val llmConfig = ConfigManager.llmConf?.takeIf { it.isConfigured }?.toLLMConfig()
            ?: throw IllegalStateException("Manual agent worker requires llm config")
        val toolList = BuiltInTools.all(this, agentDbClient, start.username).filter { it.name != "run_shell" }

        val agent = akibaAgent {
            config(llmConfig)
            tools(toolList)
            system(start.systemPrompt)
            session(start.sessionId)
            memory(persistentChatMemory(agentDbClient, start.sessionId))
            enrichSystemPrompt(true)
            auditToolCalls(true)
            maxIterations(20)
        }

        try {
            val result = agent.run(start.content)
            val status = when (result.stopReason.name) {
                "COMPLETED" -> "active"
                else -> "error"
            }
            agentDbClient.updateSession(start.sessionId, status = status)
            logger.info("AkibaUtils: manual agent turn completed, stopReason=${result.stopReason}")
        } catch (e: Exception) {
            logger.error("AkibaUtils: manual agent turn failed: ${e.message}")
            runCatching {
                agentDbClient.appendMessages(
                    start.sessionId,
                    listOf(AgentDatabaseClient.MessageData(
                        role = "assistant",
                        content = "Manual agent worker failed: ${e.message ?: e.javaClass.name}"
                    ))
                )
                agentDbClient.updateSession(start.sessionId, status = "error")
            }
            throw e
        }
    }

    private fun requestManualAgentStart(): ManualAgentStartResponse {
        val token = System.getenv("AKIBA_MANUAL_AGENT_TOKEN")
            ?: throw IllegalStateException("AKIBA_MANUAL_AGENT_TOKEN is not set")
        val port = System.getenv("AKIBA_MANUAL_AGENT_SERVER_PORT")?.toIntOrNull()
            ?: throw IllegalStateException("AKIBA_MANUAL_AGENT_SERVER_PORT is not set")
        val mapper = jacksonObjectMapper()
        val body = mapper.writeValueAsString(mapOf("token" to token))
        val request = HttpRequest.newBuilder()
            .uri(URI.create("http://127.0.0.1:$port/api/agent/internal/manual-turn/start"))
            .timeout(Duration.ofSeconds(30))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()
        val response = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build()
            .send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() !in 200..299) {
            throw IllegalStateException("Manual agent start request failed: HTTP ${response.statusCode()} ${response.body()}")
        }
        return mapper.readValue(response.body())
    }

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

    private data class ManualAgentStartResponse(
        val sessionId: String,
        val content: String,
        val systemPrompt: String,
        val username: String = "akiba"
    )

    companion object {
        private var scriptSeeded: Boolean = false
    }
}