package com.vscanner.rules

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.RandomAccessFile
import java.util.concurrent.ConcurrentHashMap

/** Hold through install, DAO reads and close. File locks also serialize cooperating processes. */
internal object RulesDbLease {
    private val mutexes = ConcurrentHashMap<String, Mutex>()

    suspend fun <T> use(context: Context, name: String, block: suspend () -> T): T {
        require(name.isNotBlank() && name == java.io.File(name).name && name !in setOf(".", ".."))
        val path = context.getDatabasePath(name)
        requireNotNull(path.parentFile).mkdirs()
        val mutex = mutexes.computeIfAbsent(path.canonicalPath) { Mutex() }
        return mutex.withLock {
            withContext(Dispatchers.IO) {
                RandomAccessFile("${path.path}.lock", "rw").use { file ->
                    file.channel.use { channel -> channel.lock().use { block() } }
                }
            }
        }
    }
}
