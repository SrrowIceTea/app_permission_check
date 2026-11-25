// 靶子 App 模块 —— 仅用于授权测试（自有设备与自有 APK）。
// 三个可独立触发的行为：过度索权（清单）、VHAL 敏感读取、JSON 外泄。
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.vscanner.targetapp"
    // android.car.jar 只存在于 android-36 / android-37.0 的 optional 目录，故必须 36。
    compileSdk = 36

    defaultConfig {
        applicationId = "com.vscanner.targetapp"
        minSdk = 29      // 真实 AAOS Car API 用法所需
        targetSdk = 35   // 目标设备：AAOS 模拟器 Android 15 / API 35
        versionCode = 1
        versionName = "1.0"
    }

    // 编译期链接平台可选库 android.car（仅编译期）。不在 manifest 声明
    // <uses-library android:name="android.car">：AAOS 设备 Car 服务恒存在，
    // 声明 uses-library 反而可能因设备实现差异导致安装/加载风险（见 DECISIONS.md）。
    useLibrary("android.car")

    packaging { jniLibs { useLegacyPackaging = true } }
    buildTypes {
        create("gadget") {
            initWith(getByName("debug"))
            matchingFallbacks += listOf("debug")
            isDebuggable = true
        }
        create("uiCoverage") {
            initWith(getByName("debug"))
            matchingFallbacks += listOf("debug")
            applicationIdSuffix = ".g1"
        }
        release {
            // 刻意不混淆、不加固：靶子 App 必须保持对审计工具完全可观察。
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // 只用平台 android.* / org.json 与 Kotlin 标准库：零 androidx / 第三方依赖，
    // 减少镜像下载面，也让 APK 内容一眼可审计。
}
