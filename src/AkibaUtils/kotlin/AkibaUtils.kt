package org.iotsplab.akiba.module

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.apache.logging.log4j.Level
import org.iotsplab.akiba.data.database.AgentDatabaseClient
import org.iotsplab.akiba.llm.agent.AgentModule
import ghidra.program.model.listing.Program
import org.iotsplab.akiba.utils.WithBundledSkills
import org.iotsplab.akiba.utils.WithScriptFile
import org.iotsplab.akiba.llm.agent.akibaAgent
import org.iotsplab.akiba.llm.memory.persistentChatMemory
import org.iotsplab.akiba.llm.tool.BuiltInTools
import org.iotsplab.akiba.managers.ConfigManager
import org.iotsplab.akiba.utils.DoNotCreateTable
import org.iotsplab.akiba.utils.WithConfigClass
import org.iotsplab.akiba.managers.WorkspaceManager
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
        "script_library/read_memory.kts",
        "script_library/elf_plt_got_info.kts",
        "script_library/list_memory_segments.kts",
        "script_library/manage_func_signature.kts",
        "script_library/manage_data_type.kts",
        "script_library/define_undefine_data.kts",
        "script_library/disassemble_and_create_function.kts",
        "script_library/write_memory.kts",
        "script_library/search_memory.kts",
    ],
    author = "Akiba",
)
@WithConfigClass(TextExportConfig::class)
@DoNotCreateTable
class AkibaUtils(
    configPath: String? = null,
    defaultConfig: Any? = null,
    id: Int = -1,
    program: Program? = null,
    properties: Map<String, String?>? = null,
    consoleLogLevel: Level = Level.INFO,
    fileLogLevel: Level = Level.INFO,
    tableName: String? = null,
) : AgentModule(configPath, defaultConfig, id, program, properties ?: mapOf(), consoleLogLevel, fileLogLevel, tableName) {

    override fun taskPrompt(): String = ""

    override suspend fun startProcess() {
        // ---- Text-export mode ----
        // When the module config is a TextExportConfig (provided by the
        // framework's --export CLI flag via the config file), render
        // project text to the workspace directory and return.  The
        // framework collects the workspace contents and zips them.
        val exportConfig = config as? TextExportConfig
        if (exportConfig != null) {
            logger.info("AkibaUtils: entering text-export mode")
            val projectName = WorkspaceManager.projectName
            val outputDir = workspaceDir.resolve("export")
            try {
                exportProjectText(
                    project = WorkspaceManager.project,
                    projectName = projectName,
                    config = exportConfig,
                    outputDir = outputDir,
                    logger = logger,
                )
                logger.info("AkibaUtils: text-export complete, output=$outputDir")
            } catch (e: Exception) {
                logger.error("AkibaUtils: text-export failed: ${e.message}", e)
            }
            return
        }

        // ---- Normal mode: install bundled scripts and skills ----
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
    private suspend fun runManualAgentTurn() {
        val start = requestManualAgentStart()
        installBundledSkillsForUser(start.username)
        val agentDbClient = AgentDatabaseClient(dbClient)
        val llmConfig = ConfigManager.llmConf?.takeIf { it.isConfigured }?.toLLMConfig()
            ?: throw IllegalStateException("Manual agent worker requires llm config")

        // Open the program from the project so tools (run_script,
        // script_library, etc.) have access to the Ghidra Program.
        // For project-based sessions (no binaryId), the program name
        // is passed via the manual-agent handshake.  For binary-based
        // sessions, AkibaModule.program was already set at construction.
        if (program == null) {
            val programName = start.programName
            if (programName != null) {
                logger.info("AkibaUtils: opening program '$programName' for manual agent turn")
                try {
                    program = WorkspaceManager.project.openProgram("/", programName, false)
                } catch (e: Exception) {
                    logger.error("AkibaUtils: failed to open program '$programName': ${e.message}", e)
                }
            }
            if (program == null) {
                // Fallback: auto-open the first program in the project root folder.
                try {
                    val project = WorkspaceManager.project
                    project.projectData.refresh(true)
                    val firstProgram = project.projectData.rootFolder.files.firstOrNull { f ->
                        val doc = f.domainObjectClass
                        doc != null && ghidra.program.model.listing.Program::class.java.isAssignableFrom(doc)
                    }
                    if (firstProgram != null) {
                        logger.info("AkibaUtils: auto-opening first program '${firstProgram.name}'")
                        program = project.openProgram("/", firstProgram.name, false)
                    } else {
                        logger.error("AkibaUtils: no program found in project root folder")
                    }
                } catch (e: Exception) {
                    logger.error("AkibaUtils: failed to auto-open program: ${e.message}", e)
                }
            }
        }
        if (program == null) {
            throw IllegalStateException(
                "AkibaUtils: no Ghidra Program is loaded. Manual agent cannot run scripts " +
                "without a program. programName from handshake: ${start.programName}"
            )
        }

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
        val username: String = "akiba",
        val programName: String? = null
    )

    companion object {
        private var scriptSeeded: Boolean = false
    }
}