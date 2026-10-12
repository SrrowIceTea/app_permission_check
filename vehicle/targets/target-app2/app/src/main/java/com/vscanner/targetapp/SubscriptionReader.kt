package com.vscanner.targetapp2

// 仅用于授权测试。subscribe/unsubscribe 签名来自 device35 实测签名表。
import android.car.Car
import android.car.hardware.CarPropertyValue
import android.car.hardware.property.CarPropertyManager
import android.content.Context
import android.os.Handler
import android.os.Looper

class SubscriptionReader(private val context: Context, private val onValue: (ReadResult) -> Unit) {
    private var car: Car? = null
    private var manager: CarPropertyManager? = null
    private val handler = Handler(Looper.getMainLooper())
    private val stopTask = Runnable { stop() }
    private val callback = object : CarPropertyManager.CarPropertyEventCallback {
        override fun onChangeEvent(value: CarPropertyValue<*>) {
            val result = if (value.status == CarPropertyValue.STATUS_AVAILABLE && value.value != null)
                "ok" else "unavailable"
            EventLog.log("SUBSCRIPTION_VALUE id=${value.propertyId} value=${value.value} result=$result")
            onValue(ReadResult("GEAR_SELECTION", value.propertyId, "INT32", VhalProps.PERM_CAR_POWERTRAIN,
                result, value.value?.toString(), null, null, System.currentTimeMillis()))
        }
        override fun onErrorEvent(propertyId: Int, areaId: Int) {
            EventLog.log("SUBSCRIPTION_ERROR id=$propertyId area=$areaId")
        }
    }

    fun start() {
        stop()
        try {
            car = Car.createCar(context)
            val cpm = car!!.getCarManager(Car.PROPERTY_SERVICE) as CarPropertyManager
            manager = cpm
            // 反射只解析已实测签名；避免 compileSdk 与车端方法面不同导致链接失败。
            val method = cpm.javaClass.getMethod("subscribePropertyEvents",
                Int::class.javaPrimitiveType, CarPropertyManager.CarPropertyEventCallback::class.java)
            val accepted = method.invoke(cpm, VhalProps.GEAR_SELECTION, callback)
            EventLog.log("SUBSCRIPTION_REGISTER accepted=$accepted (注册成功不等于收到数据)")
            handler.postDelayed(stopTask, 10_000)
        } catch (t: Throwable) {
            EventLog.log("SUBSCRIPTION_ERROR ${t.javaClass.name}: ${t.message}")
            stop()
        }
    }

    fun stop() {
        handler.removeCallbacks(stopTask)
        runCatching {
            manager?.javaClass?.getMethod("unsubscribePropertyEvents",
                CarPropertyManager.CarPropertyEventCallback::class.java)?.invoke(manager, callback)
        }.onFailure { EventLog.log("SUBSCRIPTION_STOP_ERROR ${it.message}") }
        runCatching { car?.disconnect() }
        manager = null
        car = null
    }
}
