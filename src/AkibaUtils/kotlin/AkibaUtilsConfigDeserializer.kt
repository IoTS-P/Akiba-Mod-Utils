package org.iotsplab.akiba.module

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.TextNode
import org.iotsplab.akiba.module.server.ServerConfig

class AkibaUtilsConfigDeserializer : JsonDeserializer<AkibaUtilsConfig>() {
    override fun deserialize(parser: JsonParser, context: DeserializationContext): AkibaUtilsConfig {
        val node = parser.codec.readTree<JsonNode>(parser)
        val modeNode = node.get("mode")
        val mode = if (modeNode is TextNode) modeNode.textValue() else "deps"

        val serverConfig = if (mode == "server") {
            val serverNode = node.get("server") as? JsonNode ?: return AkibaUtilsConfig(mode)
            ServerConfig(
                host = (serverNode.get("host") as? TextNode)?.textValue() ?: "0.0.0.0",
                port = serverNode.get("port")?.asInt() ?: 8080,
                jwtSecret = (serverNode.get("jwtSecret") as? TextNode)?.textValue()
                    ?: "change-me-in-production-use-long-random-string",
                dbHost = (serverNode.get("dbHost") as? TextNode)?.textValue() ?: "127.0.0.1",
                dbPort = serverNode.get("dbPort")?.asInt() ?: 5432,
                dbName = (serverNode.get("dbName") as? TextNode)?.textValue() ?: "akiba_users",
                dbUser = (serverNode.get("dbUser") as? TextNode)?.textValue() ?: "akiba",
                dbPassword = (serverNode.get("dbPassword") as? TextNode)?.textValue() ?: "akiba",
                daemonHost = (serverNode.get("daemonHost") as? TextNode)?.textValue() ?: "127.0.0.1",
                daemonPort = serverNode.get("daemonPort")?.asInt() ?: 31777
            )
        } else null

        return AkibaUtilsConfig(mode, serverConfig)
    }
}