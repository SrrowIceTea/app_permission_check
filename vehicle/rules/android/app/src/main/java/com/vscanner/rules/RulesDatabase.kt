package com.vscanner.rules

import android.content.Context
import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase

/**
 * Row counts for one android_version. Mirrors the four rule tables plus the
 * number of audit rules that are actually enabled. Aliases must match the
 * @ColumnInfo names below.
 */
data class VersionCounts(
    @ColumnInfo(name = "permissions") val permissions: Int,
    @ColumnInfo(name = "vhal_properties") val vhalProperties: Int,
    @ColumnInfo(name = "dangerous_apis") val dangerousApis: Int,
    @ColumnInfo(name = "risk_rules") val riskRules: Int,
    @ColumnInfo(name = "enabled_rules") val enabledRules: Int,
) {
    val total: Int get() = permissions + vhalProperties + dangerousApis + riskRules
    val isEmpty: Boolean get() = total == 0
}

// Query-only API. Scan events belong in a separate database.
@Dao
interface RulesDao {
    @Query("SELECT * FROM permissions WHERE android_version = :version ORDER BY permission_name")
    suspend fun permissions(version: String): List<PermissionEntity>

    @Query("SELECT * FROM vhal_properties WHERE android_version = :version ORDER BY property_key")
    suspend fun properties(version: String): List<VhalPropertyEntity>

    @Query("SELECT * FROM dangerous_apis WHERE android_version = :version ORDER BY api_key")
    suspend fun apis(version: String): List<DangerousApiEntity>

    @Query("SELECT * FROM risk_rules WHERE android_version = :version AND enabled = 1 ORDER BY rule_id")
    suspend fun activeRules(version: String): List<RiskRuleEntity>

    /** Every android_version for which any rule table has a row. */
    @Query(
        "SELECT android_version FROM permissions " +
            "UNION SELECT android_version FROM vhal_properties " +
            "UNION SELECT android_version FROM dangerous_apis " +
            "UNION SELECT android_version FROM risk_rules " +
            "ORDER BY android_version"
    )
    suspend fun versions(): List<String>

    /**
     * All five counts in one round trip. A zero-length or truncated prepackaged
     * database makes Room create an empty schema instead of failing, so these
     * counts are the only signal that distinguishes "corrupt" from "loaded" -
     * see RulesVerifier for why that matters.
     */
    @Query(
        "SELECT " +
            "(SELECT COUNT(*) FROM permissions WHERE android_version = :version) AS permissions, " +
            "(SELECT COUNT(*) FROM vhal_properties WHERE android_version = :version) AS vhal_properties, " +
            "(SELECT COUNT(*) FROM dangerous_apis WHERE android_version = :version) AS dangerous_apis, " +
            "(SELECT COUNT(*) FROM risk_rules WHERE android_version = :version) AS risk_rules, " +
            "(SELECT COUNT(*) FROM risk_rules WHERE android_version = :version AND enabled = 1) AS enabled_rules"
    )
    suspend fun counts(version: String): VersionCounts
}

@Database(
    entities = [PermissionEntity::class, VhalPropertyEntity::class,
        DangerousApiEntity::class, RiskRuleEntity::class],
    version = 1,
    exportSchema = true,
)
abstract class RulesDatabase : RoomDatabase() {
    abstract fun rules(): RulesDao

    companion object {
        const val DEFAULT_ASSET = "rules.db"
        const val DEFAULT_NAME = "vscanner-rules.db"

        /**
         * Opens the prepackaged rule database.
         *
         * Nothing is opened here: the builder is lazy and every copy or schema
         * error surfaces on the first DAO call. Callers must wrap the first query,
         * not this call.
         */
        internal fun open(
            context: Context,
            source: RulesDbSource = RulesDbSource.Asset(DEFAULT_ASSET),
            databaseName: String = DEFAULT_NAME,
        ): RulesDatabase {
            val builder = Room.databaseBuilder(
                context.applicationContext,
                RulesDatabase::class.java,
                databaseName,
            )
            builder.setJournalMode(JournalMode.TRUNCATE)
            source.applyTo(builder)
            return builder.build()
        }
    }
}

// Context above is the V-Scanner Activity/Application context, never a Frida
// system_server context. No destructive fallback or write DAO is provided.
// Room copies assets/rules.db. This API does not guarantee filesystem read-only.
