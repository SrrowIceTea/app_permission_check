package com.vscanner.rules

import android.database.DatabaseErrorHandler
import android.database.sqlite.SQLiteDatabase
import android.util.Log
import java.io.File

/** Detection must not let SQLite's default corruption handler erase the evidence. */
internal object RulesDbSqlite {
    val corruptionHandler = DatabaseErrorHandler {
        Log.e("VScannerRules", "RULES_DB_CORRUPT: preserving database and sidecars for diagnosis")
    }

    fun open(file: File, writable: Boolean = false): SQLiteDatabase = SQLiteDatabase.openDatabase(
        file.path, null,
        if (writable) SQLiteDatabase.OPEN_READWRITE else SQLiteDatabase.OPEN_READONLY,
        corruptionHandler,
    )
}
