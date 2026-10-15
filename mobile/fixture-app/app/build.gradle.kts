import groovy.json.JsonSlurper
import java.security.MessageDigest

// 移动隐私演示夹具 —— 仅用于授权测试（自有设备与自有 APK）。
//
// 三个可独立触发的行为，覆盖赛题要求的三条检测线：
//   1) 敏感数据读取（设备标识 / 位置 / 通讯录 / 应用列表 / 剪贴板 / 短信）
//   2) 同意时序（先读后索权、部分授权）
//   3) 网络外发（明文 HTTP 与 HTTPS 各一条，含可做值级匹配的标识符）
//
// 刻意保持：**零第三方依赖**（无 androidx / 无 okhttp），只用平台 API。
// 理由：镜像下载面最小、APK 一眼可审计、且钩子观测到的都是可预期的框架调用。
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.vscanner.privacydemo"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.vscanner.privacydemo"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    // Preserve the exact library/config bytes bound by gadget-provenance.json.
    packaging {
        jniLibs {
            useLegacyPackaging = true
            keepDebugSymbols += setOf("**/libgadget.so", "**/libgadget.config.so")
        }
    }
    buildTypes {
        create("gadget") {
            initWith(getByName("debug"))
            matchingFallbacks += listOf("debug")
            isDebuggable = true
        }
        release {
            // 刻意不混淆、不加固：靶子 App 必须对审计工具完全可观察。
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
    // 无依赖：全部走平台 android.* / org.json / Kotlin 标准库。
}

// Fail only the gadget variant if its verified binary/provenance has not been prepared.
val verifyGadgetFiles by tasks.registering {
    doLast {
        val provenance = file("src/gadget/assets/gadget-provenance.json")
        require(provenance.isFile) {
            "Prepare the owned fixture first: python mobile/fixture-app/gadget_prepare.py --abi x86_64"
        }
        val record = JsonSlurper().parse(provenance) as Map<*, *>
        require(record["authorized_package"] == "com.vscanner.privacydemo" &&
                record["scope"] == "self-owned-source-fixture" && record["mode"] == "gadget") {
            "Gadget provenance must identify this self-owned source fixture"
        }
        val artifacts = record["artifacts"] as? List<*> ?: error("Missing Gadget artifacts")
        require(artifacts.isNotEmpty()) { "No prepared Frida Gadget library" }
        val hashes = MessageDigest.getInstance("SHA-256")
        fun sha256(input: java.io.File) = hashes.digest(input.readBytes())
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val declared = artifacts.map { raw ->
            val artifact = raw as Map<*, *>
            val abi = artifact["abi"] as String
            require(abi in setOf("x86_64", "arm64-v8a")) { "Unsupported Gadget ABI" }
            val directory = file("src/gadget/jniLibs/$abi")
            val library = directory.resolve("libgadget.so")
            val config = directory.resolve("libgadget.config.so")
            require(library.isFile && config.isFile) { "Missing Gadget files for $abi" }
            require(sha256(library) == artifact["gadget_sha256"] &&
                    sha256(config) == artifact["config_sha256"]) { "Stale Gadget provenance for $abi" }
            abi
        }.toSet()
        val packaged = file("src/gadget/jniLibs").listFiles()?.filter { it.isDirectory }
            ?.filter { it.resolve("libgadget.so").isFile }?.map { it.name }?.toSet().orEmpty()
        require(packaged == declared) { "Undeclared stale Gadget ABI; re-prepare all present ABIs" }
    }
}
tasks.matching { it.name == "preGadgetBuild" }.configureEach { dependsOn(verifyGadgetFiles) }
