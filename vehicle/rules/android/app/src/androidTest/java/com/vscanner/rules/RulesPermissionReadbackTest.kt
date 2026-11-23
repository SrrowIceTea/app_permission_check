package com.vscanner.rules

import android.content.Context
import android.os.Build
import android.os.Process
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Exports the real DAO mapping for comparison with the independently frozen permission evidence. */
@RunWith(AndroidJUnit4::class)
class RulesPermissionReadbackTest {
    @Test
    fun readPermissionsFromInstalledAsset() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val source = RulesDbSource.Asset()
        val result = RulesDbInstaller(context).withInstalled(source, RulesDatabase.DEFAULT_NAME) { install ->
            assertTrue(install.reason, install.readable && install.contentMatch)
            assertEquals(BaselineExpectation.SHA256, install.effectiveSha256)
            val db = RulesDatabase.open(context)
            try {
                val dao = db.rules()
                val rows = JSONArray()
                for (version in dao.versions()) {
                    val permissions = dao.permissions(version)
                    assertEquals(BaselineExpectation.VERSIONS.getValue(version).permissions, permissions.size)
                    for (row in permissions) {
                        rows.put(JSONObject().apply {
                            put("permission_name", row.permissionName)
                            put("android_version", row.androidVersion)
                            put("protection_level_raw", row.protectionLevelRaw ?: JSONObject.NULL)
                            put("protection_level_value", row.protectionLevelValue ?: JSONObject.NULL)
                            put("definition_status", row.definitionStatus)
                            put("device_calibration", JSONArray(row.deviceCalibrationJson))
                        })
                    }
                }
                JSONObject().apply {
                    put("device_api", Build.VERSION.SDK_INT)
                    put("device_fingerprint", Build.FINGERPRINT)
                    put("uid", Process.myUid())
                    put("install", install.toJson())
                    put("permissions", rows)
                }
            } finally {
                db.close()
            }
        }
        File(context.filesDir, "permissions-room-readback.json").writeText(result.toString(2))
    }
}
