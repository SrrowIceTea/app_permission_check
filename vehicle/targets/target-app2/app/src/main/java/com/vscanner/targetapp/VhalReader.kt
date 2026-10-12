package com.vscanner.targetapp2

// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
//
// 行为 2：敏感数据读取。经 Car.createCar(context) → getCarManager(Car.PROPERTY_SERVICE)
// 取得 CarPropertyManager，读取 8 个 VHAL 属性。
//
// 规则一（项目铁律）：不杜撰任何 android.car 签名。本文件引用的全部来源：
//   - 8 个属性 ID：vehicle/rules/baseline_android14/rules.db vhal_properties 表（AIDL/HIDL/Java 三源交叉核对）
//   - 3 个 API 签名 getProperty(II) / getProperty(Class,II) / getFloatProperty(II)：dangerous_apis 表
//   - 6 条权限名：permissions 表
//   - Car.createCar / Car.PROPERTY_SERVICE / getCarManager / isConnected / disconnect：
//     由任务书指定调用方式，并已用 javap 对 platforms/android-36/optional/android.car.jar 编译期核实存在
//   - CarPropertyValue.getStatus/getValue/STATUS_AVAILABLE：同 jar 编译期核实；设备行为【需实测校准】

import android.car.Car
import android.car.hardware.CarPropertyValue
import android.car.hardware.property.CarPropertyManager
import android.content.Context

/** 一次属性读取的可审计结果。result 三态与审计工具规则对齐：ok / denied / error（及 unavailable）。 */
data class ReadResult(
    val property: String,
    val propertyId: Int,
    val valueType: String,
    val requiredPermission: String,
    val result: String,
    val value: String?,
    val errorClass: String?,
    val errorMessage: String?,
    val readAtUtcMs: Long
)

object VhalProps {
    // ---- 属性 ID（十进制，附十六进制），全部取自 rules.db vhal_properties 表 ----
    const val INFO_VIN = 286261504           // 0x11100100 STRING  需 CAR_IDENTIFICATION (signature|privileged)
    const val PERF_VEHICLE_SPEED = 291504647 // 0x11600207 FLOAT   需 CAR_SPEED (dangerous)
    const val GEAR_SELECTION = 289408000     // 0x11400400 INT32   需 CAR_POWERTRAIN (normal)
    const val CURRENT_GEAR = 289408001       // 0x11400401 INT32   需 CAR_POWERTRAIN (normal)
    const val PERF_ODOMETER = 291504644      // 0x11600204 FLOAT   需 CAR_MILEAGE (signature|privileged)
    const val ENGINE_RPM = 291504901         // 0x11600305 FLOAT   需 CAR_ENGINE_DETAILED (signature|privileged)
    const val FUEL_LEVEL = 291504903         // 0x11600307 FLOAT   需 CAR_ENERGY (dangerous)
    const val EV_BATTERY_LEVEL = 291504905   // 0x11600309 FLOAT   需 CAR_ENERGY (dangerous)

    // ---- 权限名，全部取自 rules.db permissions 表 ----
    const val PERM_CAR_IDENTIFICATION = "android.car.permission.CAR_IDENTIFICATION"
    const val PERM_CAR_SPEED = "android.car.permission.CAR_SPEED"
    const val PERM_CAR_ENERGY = "android.car.permission.CAR_ENERGY"
    const val PERM_CAR_MILEAGE = "android.car.permission.CAR_MILEAGE"
    const val PERM_CAR_ENGINE_DETAILED = "android.car.permission.CAR_ENGINE_DETAILED"
    const val PERM_CAR_POWERTRAIN = "android.car.permission.CAR_POWERTRAIN"

    // 8 个属性在种子库中 area_type 均为 GLOBAL。getProperty(int,int) 的第二个参数（areaId）
    // 的数值常量（VehicleAreaType.VEHICLE_AREA_TYPE_GLOBAL）不在种子库中，按规则一不得引用其名称；
    // 这里按 0 传入并保留 TODO。TODO【需实测校准】：以读取返回 status 校准 areaId=0 对应 GLOBAL。
    const val AREA_GLOBAL = 0
}

class VhalReader(private val context: Context) {

    private data class PropSpec(val name: String, val id: Int, val type: String, val perm: String)

    private val specs = listOf(
        PropSpec("INFO_VIN", VhalProps.INFO_VIN, "STRING", VhalProps.PERM_CAR_IDENTIFICATION),
        PropSpec("PERF_VEHICLE_SPEED", VhalProps.PERF_VEHICLE_SPEED, "FLOAT", VhalProps.PERM_CAR_SPEED),
        PropSpec("GEAR_SELECTION", VhalProps.GEAR_SELECTION, "INT32", VhalProps.PERM_CAR_POWERTRAIN),
        PropSpec("CURRENT_GEAR", VhalProps.CURRENT_GEAR, "INT32", VhalProps.PERM_CAR_POWERTRAIN),
        PropSpec("PERF_ODOMETER", VhalProps.PERF_ODOMETER, "FLOAT", VhalProps.PERM_CAR_MILEAGE),
        PropSpec("ENGINE_RPM", VhalProps.ENGINE_RPM, "FLOAT", VhalProps.PERM_CAR_ENGINE_DETAILED),
        PropSpec("FUEL_LEVEL", VhalProps.FUEL_LEVEL, "FLOAT", VhalProps.PERM_CAR_ENERGY),
        PropSpec("EV_BATTERY_LEVEL", VhalProps.EV_BATTERY_LEVEL, "FLOAT", VhalProps.PERM_CAR_ENERGY)
    )

    /** 依次读取全部 8 个属性。异常逐条捕获：审计工具要能区分 成功 / 被 SecurityException 拒绝 / 崩溃。 */
    fun readAll(): List<ReadResult> {
        val results = mutableListOf<ReadResult>()
        var car: Car? = null
        try {
            EventLog.log("== VHAL 读取开始（8 属性）==")
            car = Car.createCar(context)
            EventLog.log("Car.createCar 返回: $car")
            // 等待连接：轮询最多 5 秒，过程全程记日志，不做任何隐藏
            val deadline = System.currentTimeMillis() + 5000
            var attempt = 0
            while (System.currentTimeMillis() < deadline && !car.isConnected) {
                attempt++
                EventLog.log("等待 Car 连接…（第 $attempt 次轮询，200ms）")
                Thread.sleep(200)
            }
            EventLog.log("Car.isConnected = ${car.isConnected}")
            if (!car.isConnected) {
                EventLog.log("WARN: 5 秒内未连接，继续尝试读取（预期大部分报错）")
            }

            val cpm = car.getCarManager(Car.PROPERTY_SERVICE) as? CarPropertyManager
            EventLog.log("getCarManager(Car.PROPERTY_SERVICE) = ${cpm?.javaClass?.name ?: "null"}")
            if (cpm == null) {
                EventLog.log("ERROR: 取不到 CarPropertyManager（返回 null）")
                val now = System.currentTimeMillis()
                specs.forEach { s ->
                    results += ReadResult(s.name, s.id, s.type, s.perm, "error", null,
                        "IllegalStateException", "CarPropertyManager is null", now)
                }
            } else {
                specs.forEach { s -> results += readOne(cpm, s) }
                // 交叉读取：对 5 个 FLOAT 属性补一次 getFloatProperty(II)F（同为种子库危险 API）。
                // 种子库警告：单独调用 getFloatProperty 可能回退 0，故只作日志参考，不进外泄载荷。
                specs.filter { it.type == "FLOAT" }.forEach { s -> readFloatCrossCheck(cpm, s) }
            }
        } catch (t: Throwable) {
            EventLog.log("ERROR: VHAL 读取整体失败: ${t.javaClass.name}: ${t.message}")
        } finally {
            runCatching { car?.disconnect() }
                .onSuccess { EventLog.log("Car.disconnect() 已调用") }
                .onFailure { EventLog.log("Car.disconnect() 失败: ${it.message}") }
            EventLog.log("== VHAL 读取结束：${results.size} 条结果 ==")
        }
        return results
    }

    /** 主读取：getProperty(int,int)，命中 dangerous_apis 表 getProperty(II) 签名。 */
    private fun readOne(cpm: CarPropertyManager, s: PropSpec): ReadResult {
        val now = System.currentTimeMillis()
        EventLog.log("读取 ${s.name} (id=${s.id}, ${s.type}, 需 ${s.perm}) …")
        return try {
            // Java 泛型方法 <E> CarPropertyValue<E> getProperty(int,int)：类型参数只出现在返回值，
            // 星号投影不是有效推断源，必须显式给出类型实参（规则一不涉及泛型实参，值语义不变）。
            val cpv: CarPropertyValue<*> = cpm.getProperty<Any?>(s.id, VhalProps.AREA_GLOBAL)
            val status = cpv.status
            val value = cpv.value?.toString()
            if (status == CarPropertyValue.STATUS_AVAILABLE) {
                EventLog.log("  → SUCCESS ${s.name} = $value (status=$status)")
                ReadResult(s.name, s.id, s.type, s.perm, "ok", value, null, null, now)
            } else {
                EventLog.log("  → UNAVAILABLE ${s.name} (status=$status, value=$value)")
                ReadResult(s.name, s.id, s.type, s.perm, "unavailable", value, null, "status=$status", now)
            }
        } catch (e: SecurityException) {
            // 这是预期内的诚实结果：signature|privileged 权限普通应用不可能持有
            EventLog.log("  → DENIED ${s.name}: SecurityException: ${e.message}")
            ReadResult(s.name, s.id, s.type, s.perm, "denied", null, e.javaClass.name, e.message, now)
        } catch (e: Throwable) {
            EventLog.log("  → ERROR ${s.name}: ${e.javaClass.name}: ${e.message}")
            ReadResult(s.name, s.id, s.type, s.perm, "error", null, e.javaClass.name, e.message, now)
        }
    }

    /** 交叉读取：getFloatProperty(int,int)，命中 dangerous_apis 表 getFloatProperty(II)F 签名。 */
    private fun readFloatCrossCheck(cpm: CarPropertyManager, s: PropSpec) {
        EventLog.log("交叉读取 ${s.name} via getFloatProperty …")
        try {
            val f = cpm.getFloatProperty(s.id, VhalProps.AREA_GLOBAL)
            EventLog.log("  → getFloatProperty(${s.name}) = $f（参考值：单独调用可能回退 0）")
        } catch (e: SecurityException) {
            EventLog.log("  → getFloatProperty(${s.name}) DENIED: SecurityException: ${e.message}")
        } catch (e: Throwable) {
            EventLog.log("  → getFloatProperty(${s.name}) ERROR: ${e.javaClass.name}: ${e.message}")
        }
    }
}
