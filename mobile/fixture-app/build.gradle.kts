// 根构建文件。版本矩阵与 phase2/target-app 一致（已在真机验证的组合）：
// Gradle 8.13 · AGP 8.11.1 · Kotlin 2.2.0 · compileSdk 36 · JDK 21 · JVM target 17。
plugins {
    id("com.android.application") version "8.11.1" apply false
    id("org.jetbrains.kotlin.android") version "2.2.0" apply false
}
