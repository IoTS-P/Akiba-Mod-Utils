package org.iotsplab.akiba.module

import org.iotsplab.akiba.module.server.ServerConfig

data class AkibaUtilsConfig(
    val mode: String = "deps",
    val server: ServerConfig? = null
)