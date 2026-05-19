package org.iotsplab.akiba.module.server.db

import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant

data class Script(
    val id: Int,
    val userId: Int,
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
    val createdAt: Instant,
    val finishedAt: Instant?
)

data class ScriptExecution(
    val id: Int,
    val scriptId: Int,
    val binaryId: Int?,
    val status: String,
    val output: String?,
    val errorMessage: String?,
    val startedAt: Instant,
    val finishedAt: Instant?
)

object ScriptDao {
    fun createScript(
        userId: Int,
        name: String,
        description: String,
        code: String,
        language: String,
        saveResult: Boolean,
        maxOutputSize: Long
    ): Int {
        val codeSize = code.toByteArray().size
        return ServerDatabase.getConnection().prepareStatement(
            """INSERT INTO scripts (user_id, name, description, code, code_size, language, save_result, max_output_size)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id"""
        ).use { stmt ->
            stmt.setInt(1, userId)
            stmt.setString(2, name)
            stmt.setString(3, description)
            stmt.setString(4, code)
            stmt.setInt(5, codeSize)
            stmt.setString(6, language)
            stmt.setBoolean(7, saveResult)
            stmt.setLong(8, maxOutputSize)
            stmt.executeQuery().use { rs ->
                rs.next()
                rs.getInt("id")
            }
        }
    }

    fun getScriptById(id: Int): Script? {
        return ServerDatabase.getConnection().prepareStatement(
            "SELECT * FROM scripts WHERE id = ?"
        ).use { stmt ->
            stmt.setInt(1, id)
            stmt.executeQuery().use { rs ->
                if (rs.next()) rs.toScript() else null
            }
        }
    }

    fun getScriptsByUserId(userId: Int, limit: Int = 100, offset: Int = 0): List<Script> {
        val scripts = mutableListOf<Script>()
        ServerDatabase.getConnection().prepareStatement(
            """SELECT * FROM scripts WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?"""
        ).use { stmt ->
            stmt.setInt(1, userId)
            stmt.setInt(2, limit)
            stmt.setInt(3, offset)
            stmt.executeQuery().use { rs ->
                while (rs.next()) {
                    scripts.add(rs.toScript())
                }
            }
        }
        return scripts
    }

    fun updateScriptOutput(id: Int, output: String?, status: String) {
        val outputSize = output?.toByteArray()?.size ?: 0
        ServerDatabase.getConnection().prepareStatement(
            """UPDATE scripts SET output = ?, output_size = ?, status = ?, finished_at = ? WHERE id = ?"""
        ).use { stmt ->
            stmt.setString(1, output)
            stmt.setInt(2, outputSize)
            stmt.setString(3, status)
            stmt.setTimestamp(4, Timestamp.from(Instant.now()))
            stmt.setInt(5, id)
            stmt.executeUpdate()
        }
    }

    fun updateScriptOutputWithLimit(id: Int, output: String?, status: String, maxOutputSize: Long) {
        val truncatedOutput = if (output != null && output.toByteArray().size > maxOutputSize) {
            output.substring(0, maxOutputSize.toInt()) + "\n... (output truncated)"
        } else {
            output
        }
        updateScriptOutput(id, truncatedOutput, status)
    }

    fun deleteScript(id: Int): Boolean {
        return ServerDatabase.getConnection().prepareStatement(
            "DELETE FROM scripts WHERE id = ?"
        ).use { stmt ->
            stmt.setInt(1, id)
            stmt.executeUpdate() > 0
        }
    }

    fun createExecution(scriptId: Int, binaryId: Int?): Int {
        return ServerDatabase.getConnection().prepareStatement(
            """INSERT INTO script_executions (script_id, binary_id) VALUES (?, ?) RETURNING id"""
        ).use { stmt ->
            stmt.setInt(1, scriptId)
            stmt.setInt(2, binaryId ?: 0)
            stmt.executeQuery().use { rs ->
                rs.next()
                rs.getInt("id")
            }
        }
    }

    fun getExecutionById(id: Int): ScriptExecution? {
        return ServerDatabase.getConnection().prepareStatement(
            "SELECT * FROM script_executions WHERE id = ?"
        ).use { stmt ->
            stmt.setInt(1, id)
            stmt.executeQuery().use { rs ->
                if (rs.next()) rs.toExecution() else null
            }
        }
    }

    fun getExecutionsByScriptId(scriptId: Int): List<ScriptExecution> {
        val executions = mutableListOf<ScriptExecution>()
        ServerDatabase.getConnection().prepareStatement(
            """SELECT * FROM script_executions WHERE script_id = ? ORDER BY started_at DESC"""
        ).use { stmt ->
            stmt.setInt(1, scriptId)
            stmt.executeQuery().use { rs ->
                while (rs.next()) {
                    executions.add(rs.toExecution())
                }
            }
        }
        return executions
    }

    fun updateExecutionOutput(id: Int, output: String?, status: String, errorMessage: String? = null) {
        ServerDatabase.getConnection().prepareStatement(
            """UPDATE script_executions SET output = ?, status = ?, error_message = ?, finished_at = ? WHERE id = ?"""
        ).use { stmt ->
            stmt.setString(1, output)
            stmt.setString(2, status)
            stmt.setString(3, errorMessage)
            stmt.setTimestamp(4, Timestamp.from(Instant.now()))
            stmt.setInt(5, id)
            stmt.executeUpdate()
        }
    }

    fun updateExecutionOutputWithLimit(id: Int, output: String?, status: String, maxOutputSize: Long, errorMessage: String? = null) {
        val truncatedOutput = if (output != null && output.toByteArray().size > maxOutputSize) {
            output.substring(0, maxOutputSize.toInt()) + "\n... (output truncated)"
        } else {
            output
        }
        updateExecutionOutput(id, truncatedOutput, status, errorMessage)
    }

    fun deleteExecution(id: Int): Boolean {
        return ServerDatabase.getConnection().prepareStatement(
            "DELETE FROM script_executions WHERE id = ?"
        ).use { stmt ->
            stmt.setInt(1, id)
            stmt.executeUpdate() > 0
        }
    }

    fun deleteOldExecutions(olderThanDays: Int = 30) {
        ServerDatabase.getConnection().createStatement().use { stmt ->
            stmt.executeUpdate(
                "DELETE FROM script_executions WHERE started_at < now() - interval '$olderThanDays days'"
            )
        }
    }

    fun updateScript(id: Int, name: String?, description: String?, code: String?, language: String?, saveResult: Boolean?, maxOutputSize: Long?): Script? {
        ServerDatabase.getConnection().prepareStatement(
            """UPDATE scripts SET
               name = COALESCE(?, name),
               description = COALESCE(?, description),
               code = COALESCE(?, code),
               code_size = COALESCE(?, code_size),
               language = COALESCE(?, language),
               save_result = COALESCE(?, save_result),
               max_output_size = LEAST(COALESCE(?, ?), ?)
               WHERE id = ?"""
        ).use { stmt ->
            stmt.setString(1, name)
            stmt.setString(2, description)
            stmt.setString(3, code)
            stmt.setInt(4, code?.toByteArray()?.size ?: 0)
            stmt.setString(5, language)
            stmt.setBoolean(6, saveResult ?: true)
            stmt.setLong(7, maxOutputSize ?: 0)
            stmt.setLong(8, 10737418240) // MAX_OUTPUT_SIZE = 10GB in bytes
            stmt.setInt(9, id)
            stmt.executeUpdate()
        }
        return getScriptById(id)
    }

    private fun ResultSet.toScript() = Script(
        id = getInt("id"),
        userId = getInt("user_id"),
        name = getString("name"),
        description = getString("description") ?: "",
        code = getString("code"),
        codeSize = getInt("code_size"),
        language = getString("language") ?: "kotlin",
        output = getString("output"),
        outputSize = getInt("output_size"),
        status = getString("status"),
        saveResult = getBoolean("save_result"),
        maxOutputSize = getLong("max_output_size"),
        createdAt = getTimestamp("created_at").toInstant(),
        finishedAt = getTimestamp("finished_at")?.toInstant()
    )

    private fun ResultSet.toExecution() = ScriptExecution(
        id = getInt("id"),
        scriptId = getInt("script_id"),
        binaryId = getInt("binary_id").takeIf { it != 0 },
        status = getString("status"),
        output = getString("output"),
        errorMessage = getString("error_message"),
        startedAt = getTimestamp("started_at").toInstant(),
        finishedAt = getTimestamp("finished_at")?.toInstant()
    )
}