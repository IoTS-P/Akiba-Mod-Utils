package org.iotsplab.akiba.module.server.db

import org.postgresql.ds.PGSimpleDataSource
import java.sql.Connection
import java.sql.Statement

data class ServerDbConfig(
    val host: String,
    val port: Int,
    val dbName: String,
    val user: String,
    val password: String
)

object ServerDatabase {
    lateinit var config: ServerDbConfig
    private lateinit var dataSource: PGSimpleDataSource
    private lateinit var connection: Connection

    fun init(config: ServerDbConfig) {
        this.config = config
        dataSource = PGSimpleDataSource().apply {
            setServerName(config.host)
            setPortNumber(config.port)
            setDatabaseName(config.dbName)
            user = config.user
            setPassword(config.password)
        }
        connection = dataSource.connection
        initSchema()
    }

    private fun initSchema() {
        connection.createStatement().use { stmt ->
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT now()
                )
            """.trimIndent())

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    token VARCHAR(512) UNIQUE NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT now(),
                    expires_at TIMESTAMPTZ NOT NULL
                )
            """.trimIndent())

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS scripts (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    name VARCHAR(255) NOT NULL,
                    description TEXT DEFAULT '',
                    code TEXT NOT NULL,
                    code_size INTEGER DEFAULT 0,
                    language VARCHAR(20) DEFAULT 'kotlin',
                    output TEXT,
                    output_size INTEGER DEFAULT 0,
                    status VARCHAR(50) DEFAULT 'pending',
                    save_result BOOLEAN DEFAULT true,
                    max_output_size BIGINT DEFAULT 10485760,
                    created_at TIMESTAMPTZ DEFAULT now(),
                    finished_at TIMESTAMPTZ
                )
            """.trimIndent())

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS script_executions (
                    id SERIAL PRIMARY KEY,
                    script_id INTEGER REFERENCES scripts(id) ON DELETE CASCADE,
                    binary_id INTEGER,
                    status VARCHAR(50) DEFAULT 'pending',
                    output TEXT,
                    error_message TEXT,
                    started_at TIMESTAMPTZ DEFAULT now(),
                    finished_at TIMESTAMPTZ
                )
            """.trimIndent())
        }
    }

    fun getConnection(): Connection = connection

    fun close() {
        connection.close()
    }
}
