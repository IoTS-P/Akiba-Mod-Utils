package org.iotsplab.akiba.module

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.apache.logging.log4j.Level
import org.iotsplab.akiba.data.database.AgentDatabaseClient
import org.iotsplab.akiba.llm.agent.module.AgentModule
import ghidra.program.model.listing.Program
import org.iotsplab.akiba.utils.WithBundledSkills
import org.iotsplab.akiba.utils.WithScriptFile
import org.iotsplab.akiba.llm.agent.builder.akibaAgent
import org.iotsplab.akiba.llm.client.LLMConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.iotsplab.akiba.managers.ProgramScheduler
import org.iotsplab.akiba.llm.client.LLMProvider
import org.iotsplab.akiba.llm.memory.persistentChatMemory
import org.iotsplab.akiba.llm.tool.core.BuiltInTools
import org.iotsplab.akiba.managers.ConfigManager
import org.iotsplab.akiba.utils.DoNotCreateTable
import org.iotsplab.akiba.utils.WithConfigClass
import org.iotsplab.akiba.managers.WorkspaceManager
import java.net.URI
import java.nio.file.Files
import org.iotsplab.akiba.utils.InternalToken
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * AkibaUtils — the framework's general-purpose script and skill bundle.
 *
 * The scripts listed in `@WithScriptFile` below are registered automatically by
 * [AgentModule.installAnnotatedBundledScripts] before the agent's first turn, so
 * there is no hand-rolled `seedPresetScripts()` walk. Domain-specific scripts live
 * in the module that owns the workflow; see [WithScriptFile] for the format.
 */
@WithBundledSkills(["skills/binary-vuln-audit/", "skills/long-function-analysis/"])
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
        "script_library/manage_func_vars.kts",
        "script_library/define_undefine_data.kts",
        "script_library/disassemble_and_create_function.kts",
        "script_library/write_memory.kts",
        "script_library/search_memory.kts",
        "script_library/find_data_type_refs.kts",
        "script_library/export_function_analysis.kts",
        "script_library/emulate.kts"
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

    /** Per worker process: this process owns the project, so it owns the queue too. */
    private val workerScheduler = ProgramScheduler()

    /** Turns run on one thread, so a lease taken for a turn is released by the same thread. */
    private val turnDispatcher = java.util.concurrent.Executors
        .newSingleThreadExecutor { r -> Thread(r, "akiba-turn") }
        .asCoroutineDispatcher()

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

        if (System.getenv("AKIBA_PROJECT_WORKERS") == "1") {
            logger.info("AkibaUtils: resident project worker detected")
            runResidentWorker()
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
    private suspend fun runTurn(turn: TurnPayload) {
        installBundledSkillsForUser(turn.username)

        // ---- Publish the sessionId / agent on `this` so tool helpers can
        // ---- find them.  The framework's regular `startProcess` would have
        // done this in a non-manual-agent run, but the manual-agent flow
        // bypasses `super.startProcess()` entirely, so we have to wire the
        // identifiers ourselves.
        //
        // Without `this.agentSessionId` set, every tool that asks for
        // `(parent as? AgentModule)?.agentSessionId` (notably
        // `confirmFileAccess` in `WorkspaceFileTools` and
        // `RunShellTool`) returns null and auto-denies the access —
        // which means the `read_workspace_file` / `write_workspace_file`
        // confirmation modal never appears for absolute paths and the
        // user has no way to approve them.
        agentSessionId = turn.sessionId

        ensureProjectOpen()
        val agentDbClient = AgentDatabaseClient(dbClient)
        // A resident worker has no model of its own: the turn says where to send the
        // messages and with which key, so switching model or provider takes effect on the
        // next message. The config file is only a fallback for the one-shot worker.
        val llmConfig = turn.llm?.toLlmConfig()
            ?: ConfigManager.llmConf?.takeIf { it.isConfigured }?.toLLMConfig()
            ?: throw IllegalStateException("Manual agent worker requires llm config")

        // One worker serves several sessions, so they take the program in turn. The lease
        // also tells this session what the others did while it was away, which goes into
        // the system prompt for this turn only.
        val lease = workerScheduler.acquire(
            programId = turn.programName ?: turn.sessionId,
            sessionId = turn.sessionId,
            operation = "agent-turn",
        )
        try {

        // Open the program from the project so tools (run_script,
        // script_library, etc.) have access to the Ghidra Program.
        // For project-based sessions (no binaryId), the program name
        // is passed via the manual-agent handshake.  For binary-based
        // sessions, AkibaModule.program was already set at construction.
        if (program == null) {
            val programPath = turn.programName
            if (programPath != null) {
                logger.info("AkibaUtils: opening program '$programPath' for manual agent turn")
                try {
                    // programPath is a full project pathname produced
                    // by the recursive server-side lookup ("/dir/prog",
                    // or "/prog" for root-level files).  Split into
                    // folder + name for openProgram.
                    val folder = programPath.substringBeforeLast('/', "").ifEmpty { "/" }
                    val progName = programPath.substringAfterLast('/')
                    program = WorkspaceManager.project.openProgram(folder, progName, false)
                } catch (e: Exception) {
                    logger.error("AkibaUtils: failed to open program '$programPath': ${e.message}", e)
                }
            }
            if (program == null) {
                // Fallback: recursively auto-open the first program
                // found anywhere in the project (subfolders included —
                // a root-only scan misses organised projects).
                try {
                    val project = WorkspaceManager.project
                    project.projectData.refresh(true)
                    val firstProgram = findFirstProgramFile(project.projectData.rootFolder)
                    if (firstProgram != null) {
                        logger.info("AkibaUtils: auto-opening first program '${firstProgram.pathname}'")
                        val folder = firstProgram.pathname.substringBeforeLast('/', "").ifEmpty { "/" }
                        program = project.openProgram(folder, firstProgram.name, false)
                    } else {
                        logger.error("AkibaUtils: no program found anywhere in the project")
                    }
                } catch (e: Exception) {
                    logger.error("AkibaUtils: failed to auto-open program: ${e.message}", e)
                }
            }
        }
        // The project is open right now — publish its tree while that is true. Doing
        // this after the turn runs into a project the module may already have released.
        publishProjectIndex(System.currentTimeMillis())

        // A chat session started without a binary has no Ghidra program. That
        // is a supported mode: the turn still runs, but only the tools that do
        // not touch a program are registered (see [PROGRAM_FREE_TOOLS]).
        if (program == null) {
            logger.warn(
                "AkibaUtils: no Ghidra program for this session (programName=${turn.programName}) " +
                    "- running with program-free tools only"
            )
        }

        val allTools = BuiltInTools.all(this, agentDbClient, turn.username).filter { it.name != "run_shell" }
        val toolList = if (program == null) allTools.filter { it.name in PROGRAM_FREE_TOOLS } else allTools

        val agent = akibaAgent {
            config(llmConfig)
            tools(toolList)
            system(noteFor(turn.systemPrompt, lease))
            session(turn.sessionId)
            memory(persistentChatMemory(agentDbClient, turn.sessionId))
            enrichSystemPrompt(true)
            auditToolCalls(true)
            maxIterations(20)
        }

        // ---- Publish the AkibaAgent on `this` so tools that read
        // ---- `parent.agent` (e.g. `spawn_sub_agent`,
        // ---- `agent_builder_alternatives`) can find it.  The framework's
        // ---- regular `startProcess` would have done this in a
        // ---- non-manual-agent run, but the manual-agent flow bypasses
        // ---- `super.startProcess()` entirely.
        this.agent = agent

        try {
            val result = agent.run(turn.content)
            // Runtime-state model: a finished turn parks the session at
            // "closed" (the /chat route flips it back to "running" at the
            // start of the next turn).  Do NOT use the legacy "active"
            // status — the daemon's UpdateSession rejects it since the
            // runtime-state migration, which used to turn every
            // successful manual chat turn into a trailing 400 error.
            val state = when (result.stopReason.name) {
                "COMPLETED" -> org.iotsplab.akiba.llm.agent.runtime.RuntimeState.CLOSED
                else -> org.iotsplab.akiba.llm.agent.runtime.RuntimeState.ERROR
            }
            agentDbClient.setRuntimeState(
                turn.sessionId, state.wire(),
                "manual_chat_turn_${result.stopReason.name.lowercase()}"
            )
            logger.info("AkibaUtils: manual agent turn completed, stopReason=${result.stopReason}")
        } catch (e: kotlinx.coroutines.CancellationException) {
            // A stop is not a failure: the route already parked the session as closed.
            throw e
        } catch (e: Exception) {
            logger.error("AkibaUtils: manual agent turn failed: ${e.message}")
            runCatching {
                agentDbClient.appendMessages(
                    turn.sessionId,
                    listOf(AgentDatabaseClient.MessageData(
                        role = "assistant",
                        content = "Manual agent worker failed: ${e.message ?: e.javaClass.name}"
                    ))
                )
                agentDbClient.setRuntimeState(
                    turn.sessionId,
                    org.iotsplab.akiba.llm.agent.runtime.RuntimeState.ERROR.wire(),
                    "manual_chat_turn_exception"
                )
            }
            throw e
        } finally {
            // Flush queued cross-process stream chunks before this
            // worker JVM exits.  The chunk sender thread is a daemon,
            // so without this drain the response TAIL and the `done`
            // marker can be discarded at process exit — the browser's
            // streaming bubble then freezes mid-text and stalls on
            // "waiting for model…" even though the turn completed.
            // (The framework's module path does the same drain in
            // AkibaModule.startProcess; the manual-agent flow bypasses
            // that path entirely, so it must flush here.)
            runCatching {
                org.iotsplab.akiba.llm.agent.stream.StreamingChunkPusher.awaitQuiescence(3_000)
            }
        }
        } finally {
            lease.release()
            // Holding the project between turns locks the UI out of it: the Projects page
            // cannot import or list files while this process owns the .ulock.
            releaseProjectQuietly()
        }
    }

    /** The turn's system prompt, plus what other sessions did to the program meanwhile. */
    private fun noteFor(system: String, lease: ProgramScheduler.Lease): String {
        val note = lease.note() ?: return system
        return "$system\n\n$note"
    }

    /**
     * Serves turns until the process is stopped.
     *
     * The worker owns the conversation with the model: it asks for the next turn, runs it
     * with everything the request carried, and reports the outcome. Nothing calls back for
     * details, so a turn the worker is running cannot drift out of step with the server.
     */
    private suspend fun runResidentWorker() {
        while (true) {
            val turn = nextTurn() ?: continue
            val startedAt = System.currentTimeMillis()
            when (val status = runTurnUnlessStopped(turn)) {
                STATUS_OK -> reportTurnFinished(turn.turnId, STATUS_OK, null)
                STATUS_CANCELLED -> reportTurnFinished(turn.turnId, STATUS_CANCELLED, CANCELLED_MESSAGE)
                else -> {
                    logger.error("AkibaUtils: turn ${turn.turnId} failed: $status")
                    reportTurnFinished(turn.turnId, "failed", status)
                }
            }
        }
    }

    /**
     * Runs [turn] until it finishes or the user stops it.
     *
     * The worker serves every session on the project, so a stop has to reach the turn
     * and leave the process alone — cancelling the job stops the agent at its next
     * suspension point (a streamed chunk, a tool call, a wait) and nothing else.
     */
    private suspend fun runTurnUnlessStopped(turn: TurnPayload): String {
        // One thread for every turn: the program lease is a thread-bound lock, so acquire
        // and release have to happen on the same thread even across suspensions.
        val work = CoroutineScope(turnDispatcher).async {
            try {
                runTurn(turn)
                STATUS_OK
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                e.message ?: e.javaClass.simpleName
            }
        }
        val watcher = CoroutineScope(Dispatchers.IO).launch {
            while (work.isActive) {
                if (isCancelRequested(turn.turnId)) {
                    logger.info("AkibaUtils: stop requested for turn ${turn.turnId}, cancelling it")
                    work.cancel()
                    return@launch
                }
                delay(500)
            }
        }
        val status = try {
            work.await()
        } catch (e: kotlinx.coroutines.CancellationException) {
            STATUS_CANCELLED
        } finally {
            watcher.cancel()
        }
        return status
    }

    /**
     * Hands the project's file tree to the server after a turn.
     *
     * This process holds the project open, so the server cannot read the tree, and this
     * process has no database pool — the only path left is to read it here and post it.
     */
    private fun publishProjectIndex(turnStartedAtMs: Long) {
        val project = System.getenv("AKIBA_MANUAL_AGENT_PROJECT_NAME")?.takeIf { it.isNotBlank() } ?: return
        runCatching {
            // Walk the project this process already has open: reopening it here would
            // hand back a second, empty view.
            val tree = mutableListOf<Map<String, Any?>>()
            val root = WorkspaceManager.project.projectData.rootFolder
            walkProjectFolder(root, "", tree)
            logger.info(
                "AkibaUtils: index walk root={} folders={} files={} total={}",
                root.name, root.folders.size, root.files.size, tree.size)
            val payload = mapOf(
                "project" to project,
                "entries" to tree,
            )
            val body = jacksonObjectMapper().writeValueAsString(payload)
            val request = HttpRequest.newBuilder()
                .uri(URI.create("${serverBase()}/api/agent/internal/project/index"))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json")
                .header(InternalToken.HEADER, internalToken())
                .header("X-Akiba-Instance", instanceName())
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build()
            val response = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
                .send(request, HttpResponse.BodyHandlers.ofString())
            logger.info(
                "AkibaUtils: project index publish (project={}, entries={}, http={}, turn took {} ms, body={})",
                project, tree.size, response.statusCode(),
                System.currentTimeMillis() - turnStartedAtMs, response.body().take(120))
        }.onFailure { logger.warn("AkibaUtils: project index publish failed: ${it.message}") }
    }

    /** Opens the project again after the previous turn released it. */
    private fun ensureProjectOpen() {
        if (WorkspaceManager.isProjectInitialized) return
        val name = System.getenv("AKIBA_MANUAL_AGENT_PROJECT_NAME")?.takeIf { it.isNotBlank() } ?: return
        if (name.contains(':')) return   // a session-only key, not a real project
        runCatching {
            WorkspaceManager.openOrCreateInteractiveProject(
                name, false, java.nio.file.Path.of("ghidra_projects").toAbsolutePath().normalize())
            logger.info("AkibaUtils: reopened project '$name' for this turn")
        }.onFailure { logger.error("AkibaUtils: could not reopen project '$name': ${it.message}") }
    }

    /** Gives the project back so the UI can use it between turns. */
    private fun releaseProjectQuietly() {
        runCatching {
            if (WorkspaceManager.isProjectInitialized) {
                WorkspaceManager.releaseActiveProject()
                logger.info("AkibaUtils: released the project after the turn")
            }
        }.onFailure { logger.warn("AkibaUtils: release failed: ${it.message}") }
        program = null
    }

    /** Flattens the open project's tree into the rows the server's index stores. */
    private fun walkProjectFolder(
        folder: ghidra.framework.model.DomainFolder,
        prefix: String,
        out: MutableList<Map<String, Any?>>,
    ) {
        for (sub in folder.folders) {
            out.add(mapOf("path" to "$prefix${sub.name}", "name" to sub.name, "folder" to true))
            walkProjectFolder(sub, "$prefix${sub.name}/", out)
        }
        for (file in folder.files) {
            out.add(mapOf(
                "path" to "$prefix${file.name}", "name" to file.name, "folder" to false,
                "size" to file.length(), "modified" to 0,
            ))
        }
    }

    /** True once the server has been told to stop this turn. */
    private fun isCancelRequested(turnId: String): Boolean {
        if (turnId.isBlank()) return false
        return runCatching {
            val request = HttpRequest.newBuilder()
                .uri(URI.create("${serverBase()}/api/agent/internal/turn/${enc(turnId)}/cancelled"))
                .timeout(Duration.ofSeconds(5))
                .header(InternalToken.HEADER, internalToken())
                .header("X-Akiba-Instance", instanceName())
                .GET()
                .build()
            val response = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build()
                .send(request, HttpResponse.BodyHandlers.ofString())
            response.statusCode() == 200 && response.body().contains("\"cancelled\":true")
        }.getOrDefault(false)
    }

    /** Blocks on the server's long poll; null means the wait expired with no work. */
    private fun nextTurn(): TurnPayload? {
        val project = System.getenv("AKIBA_MANUAL_AGENT_PROJECT_NAME")?.takeIf { it.isNotBlank() }
            ?: throw IllegalStateException("AKIBA_MANUAL_AGENT_PROJECT_NAME is not set")
        val request = HttpRequest.newBuilder()
            .uri(URI.create("${serverBase()}/api/agent/internal/turn/next?project=${enc(project)}&waitMs=20000"))
            .timeout(Duration.ofSeconds(40))
            .header(InternalToken.HEADER, internalToken())
            .header("X-Akiba-Instance", instanceName())
            .GET()
            .build()
        val response = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()
            .send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() !in 200..299) {
            throw IllegalStateException("turn poll failed: HTTP ${response.statusCode()} ${response.body()}")
        }
        val mapper = jacksonObjectMapper()
        val root = mapper.readTree(response.body())
        val node = root.get("turn") ?: return null
        if (node.isNull) return null
        return TurnPayload(
            turnId = node.path("id").asText(),
            sessionId = node.path("sessionId").asText(),
            content = node.path("prompt").asText(),
            systemPrompt = node.path("systemPrompt").asText(""),
            username = node.path("username").asText("akiba"),
            programName = node.path("programName").takeIf { !it.isNull }?.asText(),
            llm = node.path("llm").takeIf { !it.isNull && !it.isMissingNode }?.let { wire ->
                LlmWire(
                    provider = wire.path("provider").asText(),
                    modelName = wire.path("modelName").asText(),
                    apiKey = wire.path("apiKey").asText(),
                    baseUrl = wire.path("baseUrl").takeIf { !it.isNull }?.asText(),
                )
            },
        )
    }

    private fun reportTurnFinished(turnId: String, status: String, error: String?) {
        val body = jacksonObjectMapper().writeValueAsString(
            mapOf("turnId" to turnId, "status" to status, "error" to error)
        )
        val request = HttpRequest.newBuilder()
            .uri(URI.create("${serverBase()}/api/agent/internal/turn/finished"))
            .timeout(Duration.ofSeconds(15))
            .header("Content-Type", "application/json")
            .header(InternalToken.HEADER, internalToken())
            .header("X-Akiba-Instance", instanceName())
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()
        runCatching {
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()
                .send(request, HttpResponse.BodyHandlers.discarding())
        }
    }

    private fun serverBase(): String {
        val port = System.getenv("AKIBA_MANUAL_AGENT_SERVER_PORT")?.toIntOrNull()
            ?: throw IllegalStateException("AKIBA_MANUAL_AGENT_SERVER_PORT is not set")
        return "http://127.0.0.1:$port"
    }

    private fun instanceName(): String =
        System.getenv("AKIBA_MANUAL_AGENT_INSTANCE")?.takeIf { it.isNotBlank() } ?: "akiba-instance"

    private fun internalToken(): String = try {
        Files.readString(InternalToken.file).trim()
    } catch (e: Exception) {
        throw IllegalStateException("cannot read the internal token: ${e.message}")
    }

    private fun enc(value: String): String = java.net.URLEncoder.encode(value, "UTF-8")

    /** One turn, as delivered by the server. */
    private data class TurnPayload(
        val sessionId: String,
        val content: String,
        val systemPrompt: String,
        val username: String = "akiba",
        val programName: String? = null,
        val turnId: String = "",
        val llm: LlmWire? = null,
    )

    /** Where this turn talks to the model, and with what key. */
    private data class LlmWire(
        val provider: String,
        val modelName: String,
        val apiKey: String,
        val baseUrl: String? = null,
    )

    private fun LlmWire.toLlmConfig(): LLMConfig {
        val resolved = LLMProvider.fromString(provider)
            ?: throw IllegalStateException("Unknown LLM provider '$provider'")
        return LLMConfig(
            provider = resolved,
            modelName = modelName,
            apiKey = apiKey,
            baseUrl = baseUrl,
        )
    }

    /** Recursively find the first Ghidra Program file in a project
     *  folder tree (subfolders included). */
    private fun findFirstProgramFile(
        folder: ghidra.framework.model.DomainFolder
    ): ghidra.framework.model.DomainFile? {
        folder.files.firstOrNull { f ->
            val doc = f.domainObjectClass
            doc != null && ghidra.program.model.listing.Program::class.java.isAssignableFrom(doc)
        }?.let { return it }
        for (sub in folder.folders) {
            findFirstProgramFile(sub)?.let { return it }
        }
        return null
    }


    companion object {
        private var scriptSeeded: Boolean = false

        private const val STATUS_OK = "ok"
        private const val STATUS_CANCELLED = "cancelled"
        private const val CANCELLED_MESSAGE = "cancelled by user"

        /** Tools that work without a Ghidra program (workspace, history, skills, coordination). */
        private val PROGRAM_FREE_TOOLS: Set<String> = setOf(
            "read_workspace_file", "write_workspace_file", "list_workspace_dir",
            "create_workspace_dir", "move_workspace_file", "delete_workspace_file",
            "grep_workspace",
            "query_session_history", "read_history_tool_call", "search_history_tool_calls",
            "query_memories",
            "search_skill", "read_skill",
            "list_sub_agents", "get_agent_status", "await_multiple_children",
            "ask_user_choice",
        )
    }
}