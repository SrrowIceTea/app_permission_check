package com.vscanner.rules

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import java.io.File

internal object RulesRecoveryFixtures {
    const val MARKER = "RECOVERY_NEW_LIBRARY_20261105"

    fun asset(context: Context) = context.assets.open("rules.db").use { it.readBytes() }

    fun changed(context: Context): ByteArray {
        val file = File.createTempFile("changed-rules-", ".db", context.cacheDir)
        try {
            file.writeBytes(asset(context))
            SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READWRITE).use { db ->
                db.execSQL("UPDATE permissions SET notes=? WHERE permission_name=? AND android_version=?",
                    arrayOf(MARKER, "android.car.permission.CAR_SPEED", "14"))
            }
            return file.readBytes()
        } finally { file.delete() }
    }

    fun marker(file: File): String? = SQLiteDatabase.openDatabase(
        file.path, null, SQLiteDatabase.OPEN_READONLY,
    ).use { db ->
        db.rawQuery("SELECT notes FROM permissions WHERE permission_name=? AND android_version=?",
            arrayOf("android.car.permission.CAR_SPEED", "14")).use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    }

    fun clean(context: Context, name: String) {
        context.deleteDatabase(name)
        context.getDatabasePath(name).parentFile?.listFiles()?.filter {
            it.name.startsWith("$name.") || it.name.startsWith("$name-")
        }?.forEach { check(it.delete()) { "无法清理测试文件 ${it.name}" } }
    }
}
