package org.iotsplab.akiba.module

import org.iotsplab.akiba.managers.BinaryMetadata
import org.iotsplab.akiba.module.server.AkibaServer
import org.iotsplab.akiba.module.server.ServerConfig
import org.iotsplab.akiba.utils.WithConfigClass
import org.iotsplab.akiba.utils.WithConfigDeserializer

@WithConfigClass(AkibaUtilsConfig::class)
@WithConfigDeserializer(AkibaUtilsConfigDeserializer::class)
class AkibaUtils(
    configPath: String
): AkibaModule(
    configPath = configPath
) {
    override suspend fun startProcess() {
        println("DEBUG: AkibaUtils.startProcess() called, config class = ${configClass}")
        val config = this.config as? AkibaUtilsConfig
        config?.let {
            println("DEBUG: AkibaUtils config mode = ${it.mode}, server = ${it.server}")
            when (it.mode) {
                "server" -> {
                    it.server?.let { serverConfig ->
                        println("DEBUG: Starting AkibaServer with config: ${serverConfig}")
                        AkibaServer.start(serverConfig)
                    } ?: run {
                        println("ERROR: Server mode requires server configuration")
                    }
                }
                else -> {
                    println("ERROR: Unknown mode: ${it.mode}")
                }
            }
        } ?: run {
            println("ERROR: AkibaUtils config not loaded (config = ${this.config})")
        }
    }

    override suspend fun getTaskData(key: String?): Any? {
        throw IllegalStateException("Not supported")
    }

    override suspend fun setTaskData(key: String, value: Any?) {
        throw IllegalStateException("Not supported")
    }

    override fun updateData(data: Map<String, Any?>) {
        throw IllegalStateException("Not supported")
    }

    override fun updateErr(msg: String) {
        throw IllegalStateException("Not supported")
    }

    override fun clearErr() {
        throw IllegalStateException("Not supported")
    }

    override suspend fun getMetadata(): BinaryMetadata {
        throw IllegalStateException("Not supported")
    }
}