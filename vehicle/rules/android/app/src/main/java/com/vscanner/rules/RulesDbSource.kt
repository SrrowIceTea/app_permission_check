package com.vscanner.rules

import android.content.Context
import androidx.room.RoomDatabase
import java.io.ByteArrayInputStream
import java.io.FileNotFoundException
import java.io.InputStream

/**
 * Where the prepackaged rule database comes from.
 *
 * Production always uses [Asset]. The other two exist so the failure paths can be
 * exercised on a real device: they funnel through Room's own copy routine, so the
 * exceptions they produce are the same ones production would see, rather than
 * hand-thrown stand-ins.
 */
sealed interface RulesDbSource {

    /** Feeds Room's builder. Production uses createFromAsset; the rest reuse the copy path. */
    fun applyTo(builder: RoomDatabase.Builder<RulesDatabase>)

    /** The same bytes Room will copy, for hashing. Throws if the source is absent. */
    fun openStream(context: Context): InputStream

    /** The real thing: assets/rules.db inside the APK. */
    class Asset(val path: String = RulesDatabase.DEFAULT_ASSET) : RulesDbSource {
        override fun applyTo(builder: RoomDatabase.Builder<RulesDatabase>) {
            builder.createFromAsset(path)
        }

        override fun openStream(context: Context): InputStream =
            context.assets.open(path)
    }

    /** Test only: arbitrary bytes, used for truncated and corrupt databases. */
    class Bytes(private val bytes: ByteArray) : RulesDbSource {
        override fun applyTo(builder: RoomDatabase.Builder<RulesDatabase>) {
            builder.createFromInputStream { ByteArrayInputStream(bytes) }
        }

        override fun openStream(context: Context): InputStream =
            ByteArrayInputStream(bytes)
    }

    /** Test only: an asset that is not there at all. */
    class Missing(private val path: String = RulesDatabase.DEFAULT_ASSET) : RulesDbSource {
        override fun applyTo(builder: RoomDatabase.Builder<RulesDatabase>) {
            builder.createFromInputStream { throw FileNotFoundException(path) }
        }

        override fun openStream(context: Context): InputStream =
            throw FileNotFoundException(path)
    }

    /** Used to validate a staged copy through Room before it replaces the live file. */
    class FromFile(private val file: java.io.File) : RulesDbSource {
        override fun applyTo(builder: RoomDatabase.Builder<RulesDatabase>) {
            builder.createFromFile(file)
        }

        override fun openStream(context: Context): InputStream = file.inputStream()
    }
}
