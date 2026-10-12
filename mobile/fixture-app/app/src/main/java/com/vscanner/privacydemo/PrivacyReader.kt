package com.vscanner.privacydemo

// 仅用于授权测试（自有设备与自有 APK）。
//
// 敏感数据读取集合。每个方法都**显式捕获 SecurityException 并如实回传** ——
// 被权限拒绝与读取成功是两种不同的信号，工具侧据此区分
// "denied"（试图获取拿不到的权限）与 "ok"（确实读到了）。
// 把异常吞掉返回空串会让两者在日志里长得一样，工具就无法判定。

import android.annotation.SuppressLint
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.os.Build
import android.provider.ContactsContract
import android.telephony.TelephonyManager

object PrivacyReader {

    /** 设备标识：IMEI（API 26+ 用 getImei，旧版走已废弃的 getDeviceId）。 */
    @SuppressLint("HardwareIds", "MissingPermission")
    fun deviceId(ctx: Context): String {
        val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        return try {
            val imei = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) tm.imei else tm.deviceId
            "imei=$imei"
        } catch (e: SecurityException) {
            "imei=DENIED(${e.javaClass.simpleName})"
        } catch (e: Exception) {
            "imei=ERROR(${e.javaClass.simpleName})"
        }
    }

    /** 本机号码。 */
    @SuppressLint("HardwareIds", "MissingPermission")
    fun phoneNumber(ctx: Context): String {
        val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        return try {
            "line1=${tm.line1Number}"
        } catch (e: SecurityException) {
            "line1=DENIED"
        }
    }

    /** 位置：gps 走精确、network 走粗略 —— 两种 provider 都试，让工具能看到分派差异。 */
    @SuppressLint("MissingPermission")
    fun location(ctx: Context): String {
        val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        val out = StringBuilder()
        for (provider in listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER)) {
            out.append(provider).append('=')
            out.append(try {
                val loc = lm.getLastKnownLocation(provider)
                if (loc == null) "null" else "${loc.latitude},${loc.longitude}"
            } catch (e: SecurityException) {
                "DENIED"
            } catch (e: Exception) {
                "ERROR(${e.javaClass.simpleName})"
            })
            out.append("  ")
        }
        return out.toString().trim()
    }

    /** 通讯录：ContentResolver 查询 —— 工具按 URI 前缀分派到 contacts。 */
    @SuppressLint("MissingPermission")
    fun contacts(ctx: Context): String {
        return try {
            val uri = ContactsContract.CommonDataKinds.Phone.CONTENT_URI
            ctx.contentResolver.query(uri, null, null, null, null)?.use { c ->
                "contacts.rows=${c.count}"
            } ?: "contacts.cursor=null"
        } catch (e: SecurityException) {
            "contacts=DENIED"
        } catch (e: Exception) {
            "contacts=ERROR(${e.javaClass.simpleName})"
        }
    }

    /** 应用安装列表：QUERY_ALL_PACKAGES 是安装期权限，不会有运行时同意事件。 */
    @SuppressLint("QueryPermissionsNeeded")
    fun installedApps(ctx: Context): String {
        return try {
            val pkgs = ctx.packageManager.getInstalledPackages(0)
            "installed_apps=${pkgs.size}"
        } catch (e: Exception) {
            "installed_apps=ERROR(${e.javaClass.simpleName})"
        }
    }

    /** 剪贴板：前台可读、无需运行时权限 —— 「无同意事件」的典型样本。 */
    fun clipboard(ctx: Context): String {
        return try {
            val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = cm.primaryClip
            "clipboard.items=${clip?.itemCount ?: 0}"
        } catch (e: Exception) {
            "clipboard=ERROR(${e.javaClass.simpleName})"
        }
    }

    /** 短信：本 App 业务上不需要 —— 与 READ_SMS 权限一起构成过度索权的证据对。 */
    fun sms(ctx: Context): String {
        return try {
            ctx.contentResolver.query(android.net.Uri.parse("content://sms/inbox"),
                                      null, null, null, null)?.use { c ->
                "sms.rows=${c.count}"
            } ?: "sms.cursor=null"
        } catch (e: SecurityException) {
            "sms=DENIED"
        } catch (e: Exception) {
            "sms=ERROR(${e.javaClass.simpleName})"
        }
    }

    /** 权限自查：为同意时序提供 PERM_CHECK 事件。 */
    fun checkPermission(ctx: Context, permission: String): String {
        val granted = ctx.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
        return "$permission=${if (granted) "GRANTED" else "NOT_GRANTED"}"
    }
}
