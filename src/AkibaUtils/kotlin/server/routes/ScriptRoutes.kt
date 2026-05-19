package org.iotsplab.akiba.module.server.routes

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.*
import org.iotsplab.akiba.module.server.db.ScriptDao
import org.iotsplab.akiba.module.server.db.Script as DbScript
import org.iotsplab.akiba.module.server.db.ScriptExecution as DbScriptExecution
import org.iotsplab.akiba.module.server.security.JwtService
import org.iotsplab.akiba.module.server.script.AkibaScript
import org.iotsplab.akiba.module.server.script.CompiledScript
import org.iotsplab.akiba.module.server.script.ScriptClassLoader
import org.iotsplab.akiba.module.server.script.ScriptCompiler

data class CreateScriptRequest(
    val name: String,
    val description: String = "",
    val code: String,
    val language: String = "kotlin",
    val saveResult: Boolean = true,
    val maxOutputSize: Long = 10 * 1024 * 1024
)

data class UpdateScriptRequest(
    val name: String? = null,
    val description: String? = null,
    val code: String? = null,
    val language: String? = null,
    val saveResult: Boolean? = null,
    val maxOutputSize: Long? = null
)

data class RunScriptRequest(
    val binaryIds: List<Int> = emptyList(),
    val parallel: Boolean = true
)

data class ScriptResponse(
    val id: Int,
    val name: String,
    val description: String,
    val code: String,
    val codeSize: Int,
    val language: String,
    val output: String?,
    val outputSize: Int,
    val status: String,
    val saveResult: Boolean,
    val maxOutputSize: Long,
    val createdAt: String,
    val finishedAt: String?
)

data class ScriptExecutionResponse(
    val id: Int,
    val scriptId: Int,
    val binaryId: Int?,
    val status: String,
    val output: String?,
    val errorMessage: String?,
    val startedAt: String,
    val finishedAt: String?
)

data class ScriptRunResponse(
    val executionId: Int,
    val scriptId: Int,
    val binaryIds: List<Int>,
    val status: String,
    val message: String
)

object ScriptConfig {
    const val MAX_CODE_SIZE = 1024 * 1024L // 1MB
    const val MAX_OUTPUT_SIZE = 10 * 1024 * 1024L // 10MB
    const val DEFAULT_MAX_OUTPUT_SIZE = 10 * 1024 * 1024L // 10MB
}

fun Route.scriptRoutes() {
    get("/scripts") {
        val userId = call.getUserIdFromToken() ?: run {
            call.respond(io.ktor.http.HttpStatusCode.Unauthorized, mapOf("error" to "Unauthorized"))
            return@get
        }

        val limit = call.parameters["limit"]?.toIntOrNull() ?: 100
        val offset = call.parameters["offset"]?.toIntOrNull() ?: 0

        try {
            val scripts = ScriptDao.getScriptsByUserId(userId, limit, offset)
            call.respond(mapOf("scripts" to scripts.map { it.toResponse() }))
        } catch (e: Exception) {
            call.respond(io.ktor.http.HttpStatusCode.InternalServerError,
                mapOf("error" to e.message))
        }
    }

    get("/scripts/{id}") {
        val userId = call.getUserIdFromToken() ?: run {
            call.respond(io.ktor.http.HttpStatusCode.Unauthorized, mapOf("error" to "Unauthorized"))
            return@get
        }

        val id = call.parameters["id"]?.toIntOrNull()
        if (id == null) {
            call.respond(io.ktor.http.HttpStatusCode.BadRequest, mapOf("error" to "Invalid ID"))
            return@get
        }

        try {
            val script = ScriptDao.getScriptById(id)
            if (script == null || script.userId != userId) {
                call.respond(io.ktor.http.HttpStatusCode.NotFound, mapOf("error" to "Script not found"))
                return@get
            }
            call.respond(script.toResponse())
        } catch (e: Exception) {
            call.respond(io.ktor.http.HttpStatusCode.InternalServerError,
                mapOf("error" to e.message))
        }
    }

    post("/scripts") {
        val userId = call.getUserIdFromToken() ?: run {
            call.respond(io.ktor.http.HttpStatusCode.Unauthorized, mapOf("error" to "Unauthorized"))
            return@post
        }

        val req = call.receive<CreateScriptRequest>()
        try {
            if (req.code.toByteArray().size > ScriptConfig.MAX_CODE_SIZE) {
                call.respond(io.ktor.http.HttpStatusCode.BadRequest,
                    mapOf("error" to "Code exceeds maximum size of ${ScriptConfig.MAX_CODE_SIZE} bytes"))
                return@post
            }

            val validationIssues = validateCode(req.code, req.language)
            if (validationIssues.isNotEmpty()) {
                call.respond(io.ktor.http.HttpStatusCode.BadRequest,
                    mapOf("error" to "Invalid code: ${validationIssues.joinToString("; ")}"))
                return@post
            }

            val maxOutputSize = if (req.maxOutputSize > ScriptConfig.MAX_OUTPUT_SIZE) {
                ScriptConfig.MAX_OUTPUT_SIZE
            } else {
                req.maxOutputSize
            }

            val scriptId = ScriptDao.createScript(
                userId = userId,
                name = req.name,
                description = req.description,
                code = req.code,
                language = req.language,
                saveResult = req.saveResult,
                maxOutputSize = maxOutputSize
            )

            val script = ScriptDao.getScriptById(scriptId)
            call.respond(io.ktor.http.HttpStatusCode.Created, script!!.toResponse())
        } catch (e: Exception) {
            call.respond(io.ktor.http.HttpStatusCode.InternalServerError,
                mapOf("error" to "Failed to create script: ${e.message}"))
        }
    }

    put("/scripts/{id}") {
        val userId = call.getUserIdFromToken() ?: run {
            call.respond(io.ktor.http.HttpStatusCode.Unauthorized, mapOf("error" to "Unauthorized"))
            return@put
        }

        val id = call.parameters["id"]?.toIntOrNull()
        if (id == null) {
            call.respond(io.ktor.http.HttpStatusCode.BadRequest, mapOf("error" to "Invalid ID"))
            return@put
        }

        try {
            val existingScript = ScriptDao.getScriptById(id)
            if (existingScript == null || existingScript.userId != userId) {
                call.respond(io.ktor.http.HttpStatusCode.NotFound, mapOf("error" to "Script not found"))
                return@put
            }

            val req = call.receive<UpdateScriptRequest>()
            if (req.code != null && req.code.toByteArray().size > ScriptConfig.MAX_CODE_SIZE) {
                call.respond(io.ktor.http.HttpStatusCode.BadRequest,
                    mapOf("error" to "Code exceeds maximum size of ${ScriptConfig.MAX_CODE_SIZE} bytes"))
                return@put
            }

            ScriptDao.updateScript(id, req.name, req.description, req.code, req.language, req.saveResult, req.maxOutputSize)
            val updated = ScriptDao.getScriptById(id)
            call.respond(updated!!.toResponse())
        } catch (e: Exception) {
            call.respond(io.ktor.http.HttpStatusCode.InternalServerError,
                mapOf("error" to "Failed to update script: ${e.message}"))
        }
    }

    delete("/scripts/{id}") {
        val userId = call.getUserIdFromToken() ?: run {
            call.respond(io.ktor.http.HttpStatusCode.Unauthorized, mapOf("error" to "Unauthorized"))
            return@delete
        }

        val id = call.parameters["id"]?.toIntOrNull()
        if (id == null) {
            call.respond(io.ktor.http.HttpStatusCode.BadRequest, mapOf("error" to "Invalid ID"))
            return@delete
        }

        try {
            val script = ScriptDao.getScriptById(id)
            if (script == null || script.userId != userId) {
                call.respond(io.ktor.http.HttpStatusCode.NotFound, mapOf("error" to "Script not found"))
                return@delete
            }

            ScriptDao.deleteScript(id)
            call.respond(mapOf("message" to "Script deleted"))
        } catch (e: Exception) {
            call.respond(io.ktor.http.HttpStatusCode.InternalServerError,
                mapOf("error" to "Failed to delete script: ${e.message}"))
        }
    }

    post("/scripts/{id}/run") {
        val userId = call.getUserIdFromToken() ?: run {
            call.respond(io.ktor.http.HttpStatusCode.Unauthorized, mapOf("error" to "Unauthorized"))
            return@post
        }

        val id = call.parameters["id"]?.toIntOrNull()
        if (id == null) {
            call.respond(io.ktor.http.HttpStatusCode.BadRequest, mapOf("error" to "Invalid ID"))
            return@post
        }

        try {
            val script = ScriptDao.getScriptById(id)
            if (script == null || script.userId != userId) {
                call.respond(io.ktor.http.HttpStatusCode.NotFound, mapOf("error" to "Script not found"))
                return@post
            }

            val req = call.receive<RunScriptRequest>()
            val binaryIds = req.binaryIds

            if (binaryIds.isEmpty()) {
                val executionId = ScriptDao.createExecution(script.id, null)
                CoroutineScope(Dispatchers.Default).launch {
                    executeScript(executionId, script)
                }
                call.respond(ScriptRunResponse(
                    executionId = executionId,
                    scriptId = script.id,
                    binaryIds = emptyList(),
                    status = "pending",
                    message = "Script execution started"
                ))
            } else if (binaryIds.size == 1 || !req.parallel) {
                val executionId = ScriptDao.createExecution(script.id, binaryIds.first())
                CoroutineScope(Dispatchers.Default).launch {
                    executeScriptForBinary(executionId, script, binaryIds.first())
                }
                call.respond(ScriptRunResponse(
                    executionId = executionId,
                    scriptId = script.id,
                    binaryIds = binaryIds,
                    status = "pending",
                    message = "Script execution started for single binary (serial)"
                ))
            } else {
                val executionIds = binaryIds.map { binaryId ->
                    val execId = ScriptDao.createExecution(script.id, binaryId)
                    CoroutineScope(Dispatchers.Default).launch {
                        executeScriptForBinary(execId, script, binaryId)
                    }
                    execId
                }
                call.respond(ScriptRunResponse(
                    executionId = executionIds.first(),
                    scriptId = script.id,
                    binaryIds = binaryIds,
                    status = "pending",
                    message = "Script execution started for ${binaryIds.size} binaries (parallel)"
                ))
            }
        } catch (e: Exception) {
            call.respond(io.ktor.http.HttpStatusCode.InternalServerError,
                mapOf("error" to "Failed to run script: ${e.message}"))
        }
    }

    get("/scripts/{id}/executions") {
        val userId = call.getUserIdFromToken() ?: run {
            call.respond(io.ktor.http.HttpStatusCode.Unauthorized, mapOf("error" to "Unauthorized"))
            return@get
        }

        val id = call.parameters["id"]?.toIntOrNull()
        if (id == null) {
            call.respond(io.ktor.http.HttpStatusCode.BadRequest, mapOf("error" to "Invalid ID"))
            return@get
        }

        try {
            val script = ScriptDao.getScriptById(id)
            if (script == null || script.userId != userId) {
                call.respond(io.ktor.http.HttpStatusCode.NotFound, mapOf("error" to "Script not found"))
                return@get
            }

            val executions = ScriptDao.getExecutionsByScriptId(script.id)
            call.respond(mapOf("executions" to executions.map { it.toResponse() }))
        } catch (e: Exception) {
            call.respond(io.ktor.http.HttpStatusCode.InternalServerError,
                mapOf("error" to e.message))
        }
    }

    get("/executions/{id}") {
        val userId = call.getUserIdFromToken() ?: run {
            call.respond(io.ktor.http.HttpStatusCode.Unauthorized, mapOf("error" to "Unauthorized"))
            return@get
        }

        val id = call.parameters["id"]?.toIntOrNull()
        if (id == null) {
            call.respond(io.ktor.http.HttpStatusCode.BadRequest, mapOf("error" to "Invalid ID"))
            return@get
        }

        try {
            val execution = ScriptDao.getExecutionById(id)
            if (execution == null) {
                call.respond(io.ktor.http.HttpStatusCode.NotFound, mapOf("error" to "Execution not found"))
                return@get
            }

            val script = ScriptDao.getScriptById(execution.scriptId)
            if (script == null || script.userId != userId) {
                call.respond(io.ktor.http.HttpStatusCode.NotFound, mapOf("error" to "Execution not found"))
                return@get
            }

            call.respond(execution.toResponse())
        } catch (e: Exception) {
            call.respond(io.ktor.http.HttpStatusCode.InternalServerError,
                mapOf("error" to e.message))
        }
    }
}

private fun validateCode(code: String, language: String): List<String> {
    val issues = mutableListOf<String>()
    if (code.isBlank()) {
        issues.add("Source code is empty")
        return issues
    }

    val hasClass = code.contains("class ")
    val hasInterface = code.contains("interface ")

    if (!hasClass && !hasInterface) {
        issues.add("Source must contain a class or interface definition")
    }

    return issues
}

private suspend fun executeScript(executionId: Int, script: DbScript) {
    try {
        ScriptDao.updateExecutionOutput(executionId, null, "running", null)

        val output = "Script execution placeholder - requires full framework integration"
        ScriptDao.updateScriptOutputWithLimit(
            script.id, output, "completed", script.maxOutputSize
        )
        ScriptDao.updateExecutionOutput(executionId, output, "completed", null)

        if (script.saveResult) {
            ScriptDao.updateScriptOutputWithLimit(script.id, output, "completed", script.maxOutputSize)
        }
    } catch (e: Exception) {
        val errorMsg = e.message ?: "Unknown error"
        ScriptDao.updateScriptOutputWithLimit(script.id, "Error: $errorMsg", "failed", script.maxOutputSize)
        ScriptDao.updateExecutionOutput(executionId, null, "failed", errorMsg)
    }
}

private suspend fun executeScriptForBinary(executionId: Int, script: DbScript, binaryId: Int) {
    try {
        ScriptDao.updateExecutionOutput(executionId, null, "running", null)

        val output = "Script execution for binary $binaryId - placeholder"
        ScriptDao.updateScriptOutputWithLimit(
            script.id, output, "completed", script.maxOutputSize
        )
        ScriptDao.updateExecutionOutput(executionId, output, "completed", null)

        if (script.saveResult) {
            ScriptDao.updateScriptOutputWithLimit(script.id, output, "completed", script.maxOutputSize)
        }
    } catch (e: Exception) {
        val errorMsg = e.message ?: "Unknown error"
        ScriptDao.updateScriptOutputWithLimit(script.id, "Error: $errorMsg", "failed", script.maxOutputSize)
        ScriptDao.updateExecutionOutput(executionId, null, "failed", errorMsg)
    }
}

private fun ApplicationCall.getUserIdFromToken(): Int? {
    val authHeader = request.header("Authorization")
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        return null
    }
    val token = authHeader.substring(7)
    val session = JwtService.validateToken(token)
    return session?.userId
}

private fun DbScript.toResponse() = ScriptResponse(
    id = id,
    name = name,
    description = description,
    code = code,
    codeSize = codeSize,
    language = language,
    output = output,
    outputSize = outputSize,
    status = status,
    saveResult = saveResult,
    maxOutputSize = maxOutputSize,
    createdAt = createdAt.toString(),
    finishedAt = finishedAt?.toString()
)

private fun DbScriptExecution.toResponse() = ScriptExecutionResponse(
    id = id,
    scriptId = scriptId,
    binaryId = binaryId,
    status = status,
    output = output,
    errorMessage = errorMessage,
    startedAt = startedAt.toString(),
    finishedAt = finishedAt?.toString()
)