package org.iotsplab.akiba.module

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.iotsplab.akiba.data.database.AgentDatabaseClient
import org.iotsplab.akiba.llm.agent.AgentModule
import org.iotsplab.akiba.utils.WithBundledSkills
import org.iotsplab.akiba.utils.WithScriptFile
import org.iotsplab.akiba.llm.agent.akibaAgent
import org.iotsplab.akiba.llm.memory.persistentChatMemory
import org.iotsplab.akiba.llm.tool.BuiltInTools
import org.iotsplab.akiba.managers.ConfigManager
import org.iotsplab.akiba.utils.DoNotCreateTable
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * AkibaUtils — the framework's general-purpose script and skill bundle.
 *
 * Historically this module hand-rolled a `seedPresetScripts()` walk over
 * a hard-coded list of `script_library/<file>.kts` files, then called
 * [AgentDatabaseClient.createScript] for each entry. With the v2
 * `WithScriptFile` annotation on [AgentModule], that work is now
 * declarative: every `script_library/<file>.kts` listed in the
 * annotation below is registered automatically by
 * [AgentModule.installAnnotatedBundledScripts] before the agent's
 * first turn runs.
 *
 * Domain-specific scripts (e.g. `group_functions.kts` for
 * VulnDetector) live in the module that owns the workflow rather
 * than here, so adding a new helper does NOT require editing this
 * file. See [WithScriptFile] for the format.
 */
@WithBundledSkills(["skills/binary-vuln-audit/"])
@WithScriptFile(
    [
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
        "script_library/alter_func_var.kts",
        "script_library/alter_func_signature.kts",
        "script_library/alter_label.kts",
        "script_library/manage_data_type.kts",
        "script_library/define_undefine_data.kts",
    ],
    author = "Akiba",
)
@DoNotCreateTable
class AkibaUtils: AgentModule() {

    override fun taskPrompt(): String = ""

    override suspend fun startProcess() {
        if (scriptSeeded) return
        logger.info("AkibaUtils: Installing bundled scripts and skills via AgentModule helpers...")
        try {
            installAnnotatedBundledScripts()
        } catch (e: Exception) {
            logger.warn("AkibaUtils: bundled script installation failed: ${e.message}")
        }
        try {
            installAnnotatedBundledSkills()
        } catch (e: Exception) {
            logger.warn("AkibaUtils: bundled skill installation failed: ${e.message}")
        }
        logger.info("AkibaUtils: Bundled resource installation complete.")
        scriptSeeded = true

        if (System.getenv("AKIBA_MANUAL_AGENT") == "1") {
            logger.info("AkibaUtils: manual agent worker mode detected")
            runManualAgentTurn()
        }
    }

    /** Install bundled skills from this module JAR into the target skill namespace.
     *
     * The actual extraction / installation work is now centralized in
     * [AgentModule.installBundledSkill] / [installAnnotatedBundledSkills],
     * driven by the [WithBundledSkills] annotation on this class. The
     * [runManualAgentTurn] helper below calls [installBundledSkill] directly
     * so a non-default username (the authenticated chat user) is honoured.
     */
    private fun installBundledSkillsForUser(username: String) {
        val className = this::class.qualifiedName ?: return
        val modulePath = org.iotsplab.akiba.utils.ProcedureArgumentsDeserializer.allModules[className]
        if (modulePath == null) {
            logger.warn("AkibaUtils: cannot locate module JAR, skipping bundled skill installation")
            return
        }
        for (prefix in listOf("skills/binary-vuln-audit/")) {
            installBundledSkill(modulePath, prefix, username)
        }
    }

    /**
     * Parse metadata annotations from script source header comments.
     */
    private fun runManualAgentTurn() {
        val start = requestManualAgentStart()
        installBundledSkillsForUser(start.username)
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