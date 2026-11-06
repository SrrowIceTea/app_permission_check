package com.vscanner.rules

import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileOutputStream

/** Same-directory replace only; never fall back to copying over the active database. */
internal object RulesDbFiles {
    fun syncDirectory(directory: File) {
        require(directory.isDirectory)
        val fd = Os.open(directory.path, OsConstants.O_RDONLY, 0)
        try { Os.fsync(fd) } finally { Os.close(fd) }
    }

    fun replace(source: File, target: File) {
        require(source.parentFile?.canonicalPath == target.parentFile?.canonicalPath)
        Os.rename(source.path, target.path)
        syncDirectory(requireNotNull(target.parentFile))
    }

    fun write(file: File, block: (FileOutputStream) -> Unit) {
        val temporary = File(file.parentFile, "${file.name}.part")
        FileOutputStream(temporary).use { output ->
            block(output)
            output.flush()
            output.fd.sync()
        }
        replace(temporary, file)
    }

    fun copy(source: File, target: File) = write(target) { output ->
        source.inputStream().use { it.copyTo(output) }
    }

    fun remove(file: File) {
        if (file.exists()) {
            check(file.delete()) { "无法删除 ${file.name}" }
            syncDirectory(requireNotNull(file.parentFile))
        }
    }
}
