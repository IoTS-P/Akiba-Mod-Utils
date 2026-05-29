package org.iotsplab.akiba.module

import org.iotsplab.akiba.managers.BinaryMetadata

class AkibaUtils(
    configPath: String
): AkibaModule(
    configPath = configPath
) {
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